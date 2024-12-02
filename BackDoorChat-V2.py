import socket
import threading
from datetime import datetime
import argparse
import logging
import sys
import random
import os
import base64
import os.path
import json
from pathlib import Path

# ANSI Colors and Styles
COLORS = {
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'magenta': '\033[95m',
    'cyan': '\033[96m',
    'white': '\033[97m',
    'reset': '\033[0m',
    'bold': '\033[1m',
    'dim': '\033[2m'
}

# Authentication
ACCESS_KEYS = {
    "backdoor123": "admin",
    "user123": "user",
}

# Available Commands
COMMANDS = {
    '!help': 'Show available commands',
    '!active': 'Show active users in the chat',
    '!clear': 'Clear the screen',
    '!whoami': 'Show your current username',
    '!time': 'Show current server time',
    '!pm': 'Send private message (!pm <user> <message>)',
    '!sendfile': 'Send file to user (!sendfile <user> <filepath>)',
    '!receivefile': 'Accept pending file transfer',
    '!room': 'Show current room name',
    '!kick': 'Kick a user (admin only)',
    '!ban': 'Ban a user (admin only)',
    '!mute': 'Mute a user (admin only)',
    '!unmute': 'Unmute a user (admin only)',
    '!logs': 'View recent logs (admin only)',
    '!quit': 'Exit from the chat'
}

def clear_terminal():
    """Clear terminal screen"""
    return '\033[2J\033[H'

def verify_access(key):
    """Verify access key and return role if valid"""
    return ACCESS_KEYS.get(key, None)

class RawChatServer:
    def __init__(self, host='0.0.0.0', port=55555, room_name='backdoor'):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen()
        self.clients = {}  # {socket: {'nickname': name, 'color': color, 'role': role}}
        self.room_name = room_name
        self.available_colors = ['red', 'green', 'blue', 'magenta', 'cyan', 'yellow']
        self.banned_ips = set()
        self.muted_users = set()
        self.pending_files = {}  # {client: {'sender': client, 'filename': name, 'data': data}}
        self.MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB in bytes
        self.logs_dir = Path("logs")
        self.logs_dir.mkdir(exist_ok=True)
        self.chat_log_file = self.logs_dir / f"chat_{datetime.now().strftime('%Y%m%d')}.log"
        self.event_log_file = self.logs_dir / f"events_{datetime.now().strftime('%Y%m%d')}.log"

        # Setup Logging
        self.setup_logging()

        logging.basicConfig(
            level=logging.INFO,
            format=f'{COLORS["cyan"]}%(asctime)s - %(levelname)s - %(message)s{COLORS["reset"]}'
        )
        self.logger = logging.getLogger(__name__)

    def setup_logging(self):
        """Setup logging configuration"""
        # File handler for chat logs
        chat_handler = logging.FileHandler(self.chat_log_file)
        chat_handler.setLevel(logging.INFO)
        chat_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))

        # File handler for event logs
        event_handler = logging.FileHandler(self.event_log_file)
        event_handler.setLevel(logging.INFO)
        event_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter(
            f'{COLORS["cyan"]}%(asctime)s - %(levelname)s - %(message)s{COLORS["reset"]}'
        ))

        # Setup chat logger
        self.chat_logger = logging.getLogger('chat')
        self.chat_logger.setLevel(logging.INFO)
        self.chat_logger.addHandler(chat_handler)

        # Setup event logger
        self.event_logger = logging.getLogger('events')
        self.event_logger.setLevel(logging.INFO)
        self.event_logger.addHandler(event_handler)
        self.event_logger.addHandler(console_handler)

    def log_event(self, event_type, details):
        """Log server events"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'details': details
        }
        self.event_logger.info(json.dumps(log_entry))

    def log_chat(self, nickname, message, message_type='message'):
        """Log chat messages"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': message_type,
            'nickname': nickname,
            'message': message
        }
        self.chat_logger.info(json.dumps(log_entry))

    def get_recent_logs(self, count=20):
        """Get recent log entries"""
        chat_logs = []
        event_logs = []

        try:
            with open(self.chat_log_file, 'r') as f:
                chat_logs = f.readlines()[-count:]
        except:
            pass

        try:
            with open(self.event_log_file, 'r') as f:
                event_logs = f.readlines()[-count:]
        except:
            pass

        return chat_logs, event_logs

    def cleanup_old_logs(self, days=7):
        """Clean up logs older than specified days"""
        current_time = datetime.now()
        for log_file in self.logs_dir.glob("*.log"):
            file_time = datetime.fromtimestamp(log_file.stat().st_mtime)
            if (current_time - file_time).days > days:
                log_file.unlink()
                self.log_event('log_cleanup', {
                    'file': log_file.name,
                    'age_days': (current_time - file_time).days
                })

    def get_user_color(self):
        """Get a random color for new user"""
        if self.available_colors:
            color = random.choice(self.available_colors)
            self.available_colors.remove(color)
            return color
        return 'white'

    def send_message(self, client, message, newline=True):
        """Send message to client"""
        try:
            if newline:
                message += '\r\n'
            client.send(message.encode('utf-8'))
        except:
            self.handle_disconnect(client)

    def broadcast(self, message, sender=None):
        """Broadcast message to all clients except sender"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_message = f"[{timestamp}] {message}"

        # Log the broadcast message
        if sender and sender in self.clients:
            self.log_chat(self.clients[sender]['nickname'], message)
        else:
            self.log_chat('SYSTEM', message, 'system')

        for client in self.clients:
            if client != sender:
                self.send_message(client, formatted_message)

    def send_private_message(self, sender_client, target_nick, message):
        """Send private message to specific user"""
        sender_nick = self.clients[sender_client]['nickname']
        timestamp = datetime.now().strftime('%H:%M:%S')

        for client, info in self.clients.items():
            if info['nickname'].lower() == target_nick.lower():
                # Send to target
                pm_msg = f"{COLORS['magenta']}[PM from {sender_nick}]{COLORS['reset']} {message}"
                self.send_message(client, f"[{timestamp}] {pm_msg}")
                # Send confirmation to sender
                self.send_message(sender_client, f"[{timestamp}] {COLORS['magenta']}[PM to {target_nick}]{COLORS['reset']} {message}")
                # Log private message
                self.log_chat(sender_nick, f"[PM to {target_nick}] {message}", 'private')
                return True
        return False

    def handle_file_transfer(self, sender_client, target_nick, filepath):
        """Handle file transfer between users"""
        try:
            # Check if file exists
            if not os.path.exists(filepath):
                return False, "File not found."

            # Check file size
            file_size = os.path.getsize(filepath)
            if file_size > self.MAX_FILE_SIZE:
                return False, f"File too large. Maximum size is 5MB."

            # Find target client
            target_client = None
            for client, info in self.clients.items():
                if info['nickname'].lower() == target_nick.lower():
                    target_client = client
                    break

            if not target_client:
                return False, "User not found."

            # Read and encode file
            with open(filepath, 'rb') as f:
                file_data = base64.b64encode(f.read()).decode('utf-8')

            # Store pending transfer
            self.pending_files[target_client] = {
                'sender': sender_client,
                'filename': os.path.basename(filepath),
                'data': file_data,
                'size': file_size
            }

            # Log file transfer
            self.log_event('file_transfer_initiated', {
                'sender': self.clients[sender_client]['nickname'],
                'receiver': target_nick,
                'filename': os.path.basename(filepath),
                'size': file_size
            })

            return True, "File transfer initiated."

        except Exception as e:
            self.log_event('file_transfer_failed', {
                'sender': self.clients[sender_client]['nickname'],
                'receiver': target_nick,
                'error': str(e)
            })
            return False, f"Error: {str(e)}"

    def handle_disconnect(self, client):
        """Handle client disconnection"""
        if client in self.clients:
            nickname = self.clients[client]['nickname']
            color = self.clients[client]['color']

            # Log disconnection
            self.log_event('user_disconnected', {
                'nickname': nickname,
                'role': self.clients[client]['role']
            })

            # Clean up pending file transfers
            if client in self.pending_files:
                del self.pending_files[client]

            # Clean up pending transfers where this client is the sender
            for c, transfer in list(self.pending_files.items()):
                if transfer['sender'] == client:
                    del self.pending_files[c]

            self.broadcast(f"{COLORS['yellow']}root: {COLORS[color]}{nickname}{COLORS['reset']} left the chat!")

            if color in ['red', 'green', 'blue', 'magenta', 'cyan', 'yellow']:
                self.available_colors.append(color)

            del self.clients[client]
            try:
                client.close()
            except:
                pass

    def handle_command(self, client, command):
        """Handle chat commands"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        nickname = self.clients[client]['nickname']
        user_role = self.clients[client]['role']

        # Log command usage
        self.log_chat(nickname, command, 'command')

        if command == '!help':
            help_text = f"[{timestamp}] {COLORS['yellow']}Available commands:{COLORS['reset']}\n"
            for cmd, desc in COMMANDS.items():
                # Only show admin commands to admins
                if ('admin only' in desc and user_role == 'admin') or 'admin only' not in desc:
                    help_text += f"{COLORS['cyan']}{cmd}{COLORS['reset']}: {desc}\n"
            self.send_message(client, help_text)

        elif command == '!logs' and user_role == 'admin':
            chat_logs, event_logs = self.get_recent_logs(20)
            log_text = f"{COLORS['yellow']}Recent Chat Logs:{COLORS['reset']}\n"
            for log in chat_logs:
                log_text += log
            log_text += f"\n{COLORS['yellow']}Recent Event Logs:{COLORS['reset']}\n"
            for log in event_logs:
                log_text += log
            self.send_message(client, log_text)

        elif command == '!active':
            users_text = f"[{timestamp}] {COLORS['yellow']}Active users ({len(self.clients)}):{COLORS['reset']}\n"
            for c in self.clients:
                color = self.clients[c]['color']
                nick = self.clients[c]['nickname']
                role = self.clients[c]['role']
                status = "🔇" if nick.lower() in self.muted_users else ""
                users_text += f"• {COLORS[color]}{nick}{COLORS['reset']} ({role}) {status}\n"
            self.send_message(client, users_text)

        elif command == '!clear':
            self.send_message(client, clear_terminal())
            welcome = f"Connected as {self.clients[client]['nickname']} on {self.room_name}\n"
            welcome += "-" * 60 + "\n"
            self.send_message(client, welcome)

        elif command == '!whoami':
            color = self.clients[client]['color']
            role = self.clients[client]['role']
            self.send_message(client, f"[{timestamp}] You are {COLORS[color]}{nickname}@{self.room_name}#{COLORS['reset']} ({role})")

        elif command == '!time':
            time_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.send_message(client, f"[{timestamp}] Server time: {time_now}")

        elif command == '!room':
            self.send_message(client, f"[{timestamp}] Current room: {self.room_name}")

        elif command == '!quit':
            self.send_message(client, f"{COLORS['yellow']}Goodbye! Disconnecting from chat...{COLORS['reset']}")
            self.handle_disconnect(client)
            return True

        elif command.startswith('!pm'):
            try:
                _, target, *msg_parts = command.split(' ')
                if not msg_parts:
                    self.send_message(client, f"{COLORS['red']}Usage: !pm <username> <message>{COLORS['reset']}")
                    return
                message = ' '.join(msg_parts)
                target = target.strip()

                if target.lower() == nickname.lower():
                    self.send_message(client, f"{COLORS['red']}You cannot send PM to yourself.{COLORS['reset']}")
                    return

                if self.send_private_message(client, target, message):
                    pass
                else:
                    self.send_message(client, f"{COLORS['red']}User {target} not found.{COLORS['reset']}")
            except:
                self.send_message(client, f"{COLORS['red']}Usage: !pm <username> <message>{COLORS['reset']}")

        elif command.startswith('!sendfile'):
            try:
                _, target, filepath = command.split(' ', 2)
                filepath = filepath.strip()
                target = target.strip()

                if target.lower() == nickname.lower():
                    self.send_message(client, f"{COLORS['red']}You cannot send files to yourself.{COLORS['reset']}")
                    return

                success, message = self.handle_file_transfer(client, target, filepath)
                if success:
                    sender_msg = f"{COLORS['green']}File transfer initiated. Waiting for {target} to accept...{COLORS['reset']}"
                    target_msg = (f"{COLORS['yellow']}File transfer request from {nickname}:\n"
                                  f"Filename: {os.path.basename(filepath)}\n"
                                  f"Size: {os.path.getsize(filepath)/1024:.1f}KB\n"
                                  f"Use !receivefile to accept or ignore to decline{COLORS['reset']}")

                    self.send_message(client, sender_msg)

                    # Find target and send notification
                    for c, info in self.clients.items():
                        if info['nickname'].lower() == target.lower():
                            self.send_message(c, target_msg)
                            break
                else:
                    self.send_message(client, f"{COLORS['red']}{message}{COLORS['reset']}")
            except:
                self.send_message(client, f"{COLORS['red']}Usage: !sendfile <username> <filepath>{COLORS['reset']}")

        elif command == '!receivefile':
            if client in self.pending_files:
                try:
                    transfer = self.pending_files[client]
                    sender_nick = self.clients[transfer['sender']]['nickname']

                    # Create a unique filename with a timestamp
                    base_name, ext = os.path.splitext(transfer['filename'])
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    new_filename = f"{base_name}_{timestamp}{ext}"

                    # Save file
                    with open(new_filename, 'wb') as f:
                        file_data = base64.b64decode(transfer['data'])
                        f.write(file_data)

                    # Log successful transfer
                    self.log_event('file_transfer_completed', {
                        'sender': sender_nick,
                        'receiver': nickname,
                        'filename': new_filename,
                        'size': transfer['size']
                    })

                    # Notify both parties
                    self.send_message(client, f"{COLORS['green']}File received and saved as: {new_filename}{COLORS['reset']}")
                    self.send_message(transfer['sender'],
                                      f"{COLORS['green']}File transfer completed. {nickname} received your file.{COLORS['reset']}")

                    # Clean up
                    del self.pending_files[client]

                except Exception as e:
                    self.log_event('file_transfer_failed', {
                        'sender': sender_nick,
                        'receiver': nickname,
                        'error': str(e)
                    })
                    self.send_message(client, f"{COLORS['red']}Error receiving file: {str(e)}{COLORS['reset']}")
            else:
                self.send_message(client, f"{COLORS['yellow']}No pending file transfers.{COLORS['reset']}")

        elif command.startswith('!kick') and user_role == 'admin':
            try:
                _, target = command.split(' ', 1)
                target = target.strip()
                found = False
                for c, info in self.clients.items():
                    if info['nickname'].lower() == target.lower():
                        found = True
                        self.broadcast(f"{COLORS['red']}root: {target} has been kicked by {nickname}{COLORS['reset']}")
                        self.send_message(c, f"{COLORS['red']}You have been kicked from the chat.{COLORS['reset']}")
                        self.handle_disconnect(c)
                        # Log kick event
                        self.log_event('user_kicked', {
                            'admin': nickname,
                            'target': target
                        })
                        break
                if not found:
                    self.send_message(client, f"{COLORS['red']}User {target} not found.{COLORS['reset']}")
            except:
                self.send_message(client, f"{COLORS['red']}Usage: !kick <username>{COLORS['reset']}")

        elif command.startswith('!ban') and user_role == 'admin':
            try:
                _, target = command.split(' ', 1)
                target = target.strip()
                for c, info in self.clients.items():
                    if info['nickname'].lower() == target.lower():
                        client_ip = c.getpeername()[0]
                        self.banned_ips.add(client_ip)
                        self.broadcast(f"{COLORS['red']}root: {target} has been banned by {nickname}{COLORS['reset']}")
                        self.send_message(c, f"{COLORS['red']}You have been banned from the chat.{COLORS['reset']}")
                        # Log ban event
                        self.log_event('user_banned', {
                            'admin': nickname,
                            'target': target,
                            'ip': client_ip
                        })
                        self.handle_disconnect(c)
                        break
            except:
                self.send_message(client, f"{COLORS['red']}Usage: !ban <username>{COLORS['reset']}")

        elif command.startswith('!mute') and user_role == 'admin':
            try:
                _, target = command.split(' ', 1)
                target = target.strip()
                if target.lower() in self.muted_users:
                    self.send_message(client, f"{COLORS['yellow']}User {target} is already muted.{COLORS['reset']}")
                else:
                    self.muted_users.add(target.lower())
                    self.broadcast(f"{COLORS['yellow']}root: {target} has been muted by {nickname}{COLORS['reset']}")
                    # Log mute event
                    self.log_event('user_muted', {
                        'admin': nickname,
                        'target': target
                    })
            except:
                self.send_message(client, f"{COLORS['red']}Usage: !mute <username>{COLORS['reset']}")

        elif command.startswith('!unmute') and user_role == 'admin':
            try:
                _, target = command.split(' ', 1)
                target = target.strip()
                if target.lower() in self.muted_users:
                    self.muted_users.remove(target.lower())
                    self.broadcast(f"{COLORS['yellow']}root: {target} has been unmuted by {nickname}{COLORS['reset']}")
                    # Log unmute event
                    self.log_event('user_unmuted', {
                        'admin': nickname,
                        'target': target
                    })
                else:
                    self.send_message(client, f"{COLORS['yellow']}User {target} is not muted.{COLORS['reset']}")
            except:
                self.send_message(client, f"{COLORS['red']}Usage: !unmute <username>{COLORS['reset']}")

        else:
            self.send_message(client, f"[{timestamp}] {COLORS['red']}Unknown command. Type !help for available commands.{COLORS['reset']}")

    def handle_client(self, client, address):
        """Handle individual client connection"""
        # Log connection attempt
        self.log_event('connection_attempt', {
            'ip': address[0],
            'port': address[1]
        })

        # Check for banned IP
        client_ip = address[0]
        if client_ip in self.banned_ips:
            self.log_event('connection_rejected', {
                'ip': client_ip,
                'reason': 'banned'
            })
            self.send_message(client, f"{COLORS['red']}Your IP has been banned from this chat.{COLORS['reset']}")
            client.close()
            return

        # Initial welcome
        welcome = clear_terminal()
        welcome += f"{COLORS['cyan']}╭{'─' * 58}╮{COLORS['reset']}\n"
        welcome += f"{COLORS['cyan']}│{' ' * 22}BackDoor Chat{' ' * 24}│{COLORS['reset']}\n"
        welcome += f"{COLORS['cyan']}╰{'─' * 58}╯{COLORS['reset']}\n\n"
        self.send_message(client, welcome)

        # Authentication
        max_attempts = 3
        attempts = 0
        authenticated = False
        user_role = None

        while attempts < max_attempts and not authenticated:
            remaining = max_attempts - attempts
            self.send_message(client, f"{COLORS['yellow']}Enter access key ({remaining} attempts remaining): {COLORS['reset']}", newline=False)
            try:
                key = client.recv(1024).decode('utf-8').strip()
                user_role = verify_access(key)

                if user_role:
                    authenticated = True
                    self.send_message(client, f"{COLORS['green']}Access granted! Role: {user_role}{COLORS['reset']}")
                    self.log_event('authentication_success', {
                        'ip': client_ip,
                        'role': user_role
                    })
                else:
                    attempts += 1
                    if attempts < max_attempts:
                        self.send_message(client, f"{COLORS['red']}Invalid key. Please try again.{COLORS['reset']}")
                    else:
                        self.send_message(client, f"{COLORS['red']}Too many failed attempts. Connection terminated.{COLORS['reset']}")
                        self.log_event('authentication_failed', {
                            'ip': client_ip,
                            'attempts': attempts
                        })
                        client.close()
                        return
            except:
                client.close()
                return

        if not authenticated:
            return

        # Get nickname after authentication
        self.send_message(client, f"\n{COLORS['cyan']}Choose an alias: {COLORS['reset']}", newline=False)

        try:
            nickname = client.recv(1024).decode('utf-8').strip()
            # Check if nickname is already taken
            for c in self.clients:
                if self.clients[c]['nickname'].lower() == nickname.lower():
                    self.send_message(client, f"{COLORS['red']}Nickname already taken. Please try again.{COLORS['reset']}")
                    client.close()
                    return

            color = self.get_user_color()
            self.clients[client] = {
                'nickname': nickname,
                'color': color,
                'role': user_role
            }

            # Log successful connection
            self.log_event('user_connected', {
                'nickname': nickname,
                'ip': client_ip,
                'role': user_role
            })

            # Clear screen and show welcome
            self.send_message(client, clear_terminal())
            self.send_message(client, f"Connected as {COLORS[color]}{nickname}@{self.room_name}#{COLORS['reset']} ({user_role})")
            self.send_message(client, "Type !help for available commands")
            self.send_message(client, "-" * 60 + "\n")

            # Announce new user
            self.broadcast(f"{COLORS['yellow']}root: {COLORS[color]}{nickname}{COLORS['reset']} joined the chat!")

            while True:
                try:
                    message = client.recv(1024).decode('utf-8').strip()
                    if not message:
                        break

                    if message.startswith('!'):
                        if message == '!quit':
                            self.handle_command(client, message)
                            break  # Exit the loop after quit
                        else:
                            self.handle_command(client, message)
                    else:
                        # Check if user is muted
                        if nickname.lower() in self.muted_users and not message.startswith('!'):
                            self.send_message(client, f"{COLORS['red']}You are muted and cannot send messages.{COLORS['reset']}")
                            continue

                        timestamp = datetime.now().strftime('%H:%M:%S')
                        formatted = f"[{timestamp}] {COLORS[color]}{nickname}@{self.room_name}#{COLORS['reset']} {message}"
                        self.broadcast(formatted, client)

                except:
                    break

        except:
            pass

        self.handle_disconnect(client)

    def start(self):
        """Start the chat server"""
        # Clean up old logs on startup
        self.cleanup_old_logs()

        # Log server start
        self.log_event('server_start', {
            'host': self.server.getsockname()[0],
            'port': self.server.getsockname()[1],
            'room': self.room_name
        })

        self.logger.info(f"Server running on port {self.server.getsockname()[1]}")
        print(f"Server is running on {self.server.getsockname()[0]}:{self.server.getsockname()[1]}")

        while True:
            try:
                client, address = self.server.accept()
                self.logger.info(f"New connection from {address}")

                thread = threading.Thread(target=self.handle_client, args=(client, address))
                thread.daemon = True
                thread.start()

            except Exception as e:
                self.logger.error(f"Error accepting connection: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Enhanced CLI Chat Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host address to bind on')
    parser.add_argument('--port', type=int, default=55555, help='Port number')
    parser.add_argument('--room', default='backdoor', help='Chat room name')

    args = parser.parse_args()

    try:
        server = RawChatServer(host=args.host, port=args.port, room_name=args.room)
        server.start()
    except KeyboardInterrupt:
        print(f"\n{COLORS['yellow']}Shutting down...{COLORS['reset']}")
        # Log server shutdown
        server.log_event('server_shutdown', {
            'reason': 'keyboard_interrupt'
        })
        sys.exit(0)
