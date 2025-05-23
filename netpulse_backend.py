#!/usr/bin/env python3

import asyncio
import json
import time
import statistics
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging
from dataclasses import dataclass, asdict
import subprocess
import re
import platform
import threading
from collections import deque, defaultdict

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit


@dataclass
class ServerConfig:
    name: str
    host: str
    location: str


@dataclass
class PingResult:
    timestamp: float
    server_name: str
    host: str
    latency: Optional[float]
    packet_loss: bool
    error_message: Optional[str] = None


class NetworkMonitor:
    def __init__(self):
        self.servers = [
            ServerConfig("Google DNS", "8.8.8.8", "Global"),
            ServerConfig("Cloudflare DNS", "1.1.1.1", "Global"),
            ServerConfig("OpenDNS", "208.67.222.222", "Global"),
            ServerConfig("Quad9 DNS", "9.9.9.9", "Global"),
            ServerConfig("Google", "google.com", "Global"),
            ServerConfig("GitHub", "github.com", "Global"),
        ]

        self.max_history = 1000
        self.ping_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.max_history))
        self.stats: Dict[str, Dict] = {}
        self.monitoring_active = False
        self.ping_interval = 2.0

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def _execute_ping(self, host: str, count: int = 1, timeout: int = 3) -> Tuple[bool, Optional[float], Optional[str]]:
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
            else:
                cmd = ["ping", "-c", str(count), "-W", str(timeout), host]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)

            if result.returncode != 0:
                return False, None, result.stderr.strip()

            output = result.stdout

            if system == "windows":
                latency_match = re.search(r'时间[<=](\d+)ms|time[<=](\d+)ms', output, re.IGNORECASE)
                if not latency_match:
                    latency_match = re.search(r'(\d+)ms', output)
                if latency_match:
                    latency = float(latency_match.group(1))
                    return True, latency, None
            else:
                rtt_match = re.search(r'round-trip min/avg/max/stddev = (\d+\.?\d*)/(\d+\.?\d*)/(\d+\.?\d*)', output)
                if rtt_match:
                    latency = float(rtt_match.group(2))
                    return True, latency, None

                time_match = re.search(r'time=(\d+\.?\d*)', output)
                if time_match:
                    latency = float(time_match.group(1))
                    return True, latency, None

            return False, None, "Parse error"

        except subprocess.TimeoutExpired:
            return False, None, "Timeout"
        except Exception as e:
            return False, None, str(e)

    def ping_server(self, server: ServerConfig) -> PingResult:
        timestamp = time.time()
        success, latency, error = self._execute_ping(server.host)

        result = PingResult(
            timestamp=timestamp,
            server_name=server.name,
            host=server.host,
            latency=latency,
            packet_loss=not success,
            error_message=error
        )

        self.ping_history[server.name].append(result)
        self._update_stats(server.name)

        return result

    def _update_stats(self, server_name: str):
        history = list(self.ping_history[server_name])
        if not history:
            return

        recent_cutoff = time.time() - 600
        recent_pings = [p for p in history if p.timestamp > recent_cutoff][-100:]

        if not recent_pings:
            return

        successful_pings = [p for p in recent_pings if not p.packet_loss]
        total_pings = len(recent_pings)
        successful_count = len(successful_pings)

        packet_loss_rate = ((total_pings - successful_count) / total_pings) * 100

        if successful_pings:
            latencies = [p.latency for p in successful_pings]
            avg_latency = statistics.mean(latencies)
            min_latency = min(latencies)
            max_latency = max(latencies)
            jitter = statistics.stdev(latencies) if len(latencies) > 1 else 0
        else:
            avg_latency = min_latency = max_latency = jitter = None

        self.stats[server_name] = {
            'avg_latency': avg_latency,
            'min_latency': min_latency,
            'max_latency': max_latency,
            'jitter': jitter,
            'packet_loss_rate': packet_loss_rate,
            'total_pings': total_pings,
            'successful_pings': successful_count,
            'last_updated': time.time()
        }

    async def monitor_all_servers(self):
        self.logger.info("Starting monitoring...")
        self.monitoring_active = True

        while self.monitoring_active:
            start_time = time.time()

            tasks = []
            for server in self.servers:
                task = asyncio.create_task(self._async_ping_server(server))
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    self.logger.error(f"Error pinging {self.servers[i].name}: {result}")
                else:
                    if result.packet_loss:
                        self.logger.warning(f"{result.server_name}: LOST - {result.error_message}")
                    else:
                        self.logger.info(f"{result.server_name}: {result.latency:.1f}ms")

            elapsed = time.time() - start_time
            sleep_time = max(0, self.ping_interval - elapsed)
            await asyncio.sleep(sleep_time)

    async def _async_ping_server(self, server: ServerConfig) -> PingResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.ping_server, server)

    def stop_monitoring(self):
        self.monitoring_active = False
        self.logger.info("Monitoring stopped")

    def get_recent_data(self, server_name: str = None, limit: int = 50) -> Dict:
        if server_name:
            history = list(self.ping_history[server_name])[-limit:]
            return {
                'server': server_name,
                'data': [asdict(ping) for ping in history],
                'stats': self.stats.get(server_name, {})
            }
        else:
            result = {}
            for name in self.ping_history.keys():
                history = list(self.ping_history[name])[-limit:]
                result[name] = {
                    'data': [asdict(ping) for ping in history],
                    'stats': self.stats.get(name, {})
                }
            return result

    def get_server_list(self) -> List[Dict]:
        return [asdict(server) for server in self.servers]


app = Flask(__name__)
app.config['SECRET_KEY'] = 'netpulse_key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

monitor = NetworkMonitor()


@app.route('/')
def home():
    return jsonify({
        'service': 'NetPulse Backend',
        'status': 'running',
        'endpoints': {
            'servers': '/api/servers',
            'data': '/api/data',
            'stats': '/api/stats',
            'status': '/api/status',
            'start': '/api/start (POST)',
            'stop': '/api/stop (POST)',
            'health': '/health'
        }
    })


@app.route('/api/servers')
def get_servers():
    return jsonify(monitor.get_server_list())


@app.route('/api/data')
def get_data():
    server = request.args.get('server')
    limit = int(request.args.get('limit', 50))
    data = monitor.get_recent_data(server, limit)
    return jsonify(data)


@app.route('/api/stats')
def get_stats():
    return jsonify(monitor.stats)


@app.route('/api/status')
def get_status():
    return jsonify({
        'monitoring': monitor.monitoring_active,
        'servers_count': len(monitor.servers),
        'total_pings': sum(len(history) for history in monitor.ping_history.values()),
        'uptime': time.time()
    })


@app.route('/api/start', methods=['POST'])
def start_monitoring():
    if not monitor.monitoring_active:
        def run_monitor():
            asyncio.run(monitor.monitor_all_servers())

        thread = threading.Thread(target=run_monitor, daemon=True)
        thread.start()
        return jsonify({'status': 'started'})
    else:
        return jsonify({'status': 'already_running'})


@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    monitor.stop_monitoring()
    return jsonify({'status': 'stopped'})


@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('status', {'monitoring': monitor.monitoring_active})


@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')


@socketio.on('request_data')
def handle_data_request(data):
    server = data.get('server')
    limit = data.get('limit', 20)
    response_data = monitor.get_recent_data(server, limit)
    emit('data_update', response_data)


def background_task():
    while True:
        if monitor.monitoring_active:
            latest_data = monitor.get_recent_data(limit=10)
            socketio.emit('live_update', latest_data)
        socketio.sleep(5)


socketio.start_background_task(background_task)


@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})


if __name__ == '__main__':
    print("NetPulse Backend Starting...")
    print("Server: http://localhost:5005")


    def auto_start():
        time.sleep(2)

        def run_monitor():
            asyncio.run(monitor.monitor_all_servers())

        thread = threading.Thread(target=run_monitor, daemon=True)
        thread.start()


    threading.Thread(target=auto_start, daemon=True).start()
    socketio.run(app, host='0.0.0.0', port=5005, debug=False)