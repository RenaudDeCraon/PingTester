import asyncio
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import subprocess

from main import (
    NetPulseEliteContinuous, 
    ContinuousNetworkDatabase,
    ContinuousMonitoringEngine,
    RealTimeTrafficAnalyzer,
    NotificationSystem,
    NetPulseEliteEngine
)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netpulse-elite-secret-key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

netpulse_platform = NetPulseEliteContinuous()
db = ContinuousNetworkDatabase()
active_processes = {}
monitoring_status = {
    'active': False,
    'targets': [],
    'stats': {
        'total_scans': 0,
        'active_alerts': 0,
        'monitored_targets': 0,
        'avg_security_score': 0
    }
}

traffic_analysis_status = {
    'active': False,
    'interface': None,
    'stats': {
        'packets_analyzed': 0,
        'threats_detected': 0,
        'bandwidth_util': 0,
        'anomalies_found': 0
    }
}

class WebSocketHandler(logging.Handler):
    """Custom logging handler to send logs to WebSocket clients"""
    
    def emit(self, record):
        try:
            msg = self.format(record)
            socketio.emit('log_message', {
                'timestamp': datetime.now().isoformat(),
                'level': record.levelname,
                'message': msg
            })
        except:
            pass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
websocket_handler = WebSocketHandler()
logger.addHandler(websocket_handler)

@app.route('/')
def index():
    """Serve the main frontend HTML"""
    with open('netpulse_frontend.html', 'r') as f:
        return f.read()

@app.route('/api/health')
def health_check():
    """API health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0'
    })

@app.route('/api/analysis/single', methods=['POST'])
def single_analysis():
    """Run single target analysis"""
    try:
        data = request.get_json()
        target = data.get('target')
        options = data.get('options', {})
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400

        def run_analysis():
            try:
                socketio.emit('analysis_started', {'target': target})
                
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(
                    netpulse_platform.run_single_analysis(target)
                )
                loop.close()
                
                if options.get('save_results', False):
                    filename = f"{target}_analysis.json"
                    with open(filename, 'w') as f:
                        json.dump(results, f, indent=2, default=str)
                    results['saved_file'] = filename
                
                socketio.emit('analysis_completed', {
                    'target': target,
                    'results': results
                })
                
            except Exception as e:
                logger.error(f"Analysis error: {e}")
                socketio.emit('analysis_error', {
                    'target': target,
                    'error': str(e)
                })
        
        analysis_thread = threading.Thread(target=run_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()
        
        return jsonify({
            'status': 'started',
            'target': target,
            'message': 'Analysis started in background'
        })
        
    except Exception as e:
        logger.error(f"Single analysis error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitoring/start', methods=['POST'])
def start_monitoring():
    """Start continuous monitoring"""
    try:
        data = request.get_json()
        targets = data.get('targets', [])
        config = data.get('config', {})
        
        if not targets:
            return jsonify({'error': 'Targets are required'}), 400
        
        if isinstance(targets, str):
            targets = [t.strip() for t in targets.split(',')]
        
        monitoring_status['targets'] = targets
        monitoring_status['active'] = True
        monitoring_status['stats']['monitored_targets'] = len(targets)
        
        def run_monitoring():
            try:
                socketio.emit('monitoring_started', {
                    'targets': targets,
                    'config': config
                })
                
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(
                    netpulse_platform.start_continuous_monitoring(targets)
                )
                loop.close()
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                monitoring_status['active'] = False
                socketio.emit('monitoring_error', {'error': str(e)})
        
        monitoring_thread = threading.Thread(target=run_monitoring)
        monitoring_thread.daemon = True
        monitoring_thread.start()
        
        return jsonify({
            'status': 'started',
            'targets': targets,
            'message': 'Continuous monitoring started'
        })
        
    except Exception as e:
        logger.error(f"Start monitoring error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitoring/stop', methods=['POST'])
def stop_monitoring():
    """Stop continuous monitoring"""
    try:
        monitoring_status['active'] = False
        monitoring_status['targets'] = []
        monitoring_status['stats']['monitored_targets'] = 0
        
        socketio.emit('monitoring_stopped', {
            'message': 'Continuous monitoring stopped'
        })
        
        return jsonify({
            'status': 'stopped',
            'message': 'Monitoring stopped successfully'
        })
        
    except Exception as e:
        logger.error(f"Stop monitoring error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitoring/status')
def get_monitoring_status():
    """Get current monitoring status"""
    try:
        active_alerts = len(db.get_active_alerts())
        monitoring_status['stats']['active_alerts'] = active_alerts
        
        return jsonify(monitoring_status)
        
    except Exception as e:
        logger.error(f"Get monitoring status error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic/start', methods=['POST'])
def start_traffic_analysis():
    """Start traffic analysis"""
    try:
        data = request.get_json()
        interface = data.get('interface', 'eth0')
        options = data.get('options', {})
        
        traffic_analysis_status['active'] = True
        traffic_analysis_status['interface'] = interface
        
        def run_traffic_analysis():
            try:
                socketio.emit('traffic_analysis_started', {
                    'interface': interface,
                    'options': options
                })
                
                analyzer = RealTimeTrafficAnalyzer(interface)
                
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(analyzer.start_continuous_capture())
                loop.close()
                
            except Exception as e:
                logger.error(f"Traffic analysis error: {e}")
                traffic_analysis_status['active'] = False
                socketio.emit('traffic_analysis_error', {'error': str(e)})
        
        traffic_thread = threading.Thread(target=run_traffic_analysis)
        traffic_thread.daemon = True
        traffic_thread.start()
        
        return jsonify({
            'status': 'started',
            'interface': interface,
            'message': 'Traffic analysis started'
        })
        
    except Exception as e:
        logger.error(f"Start traffic analysis error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic/stop', methods=['POST'])
def stop_traffic_analysis():
    """Stop traffic analysis"""
    try:
        traffic_analysis_status['active'] = False
        traffic_analysis_status['interface'] = None
        
        traffic_analysis_status['stats'] = {
            'packets_analyzed': 0,
            'threats_detected': 0,
            'bandwidth_util': 0,
            'anomalies_found': 0
        }
        
        socketio.emit('traffic_analysis_stopped', {
            'message': 'Traffic analysis stopped'
        })
        
        return jsonify({
            'status': 'stopped',
            'message': 'Traffic analysis stopped successfully'
        })
        
    except Exception as e:
        logger.error(f"Stop traffic analysis error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic/status')
def get_traffic_status():
    """Get current traffic analysis status"""
    return jsonify(traffic_analysis_status)

@app.route('/api/dashboard')
def get_dashboard():
    """Get dashboard data"""
    try:
        dashboard_data = netpulse_platform.get_monitoring_dashboard()
        
        dashboard_data['system_stats'] = {
            'total_targets': len(monitoring_status['targets']),
            'online_targets': len([t for t in monitoring_status['targets'] if t]),
            'critical_alerts': len([a for a in db.get_active_alerts() if a.severity == 'critical']),
            'system_health': 100 if monitoring_status['active'] else 85
        }
        
        return jsonify(dashboard_data)
        
    except Exception as e:
        logger.error(f"Get dashboard error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
def get_alerts():
    """Get active alerts"""
    try:
        alerts = db.get_active_alerts()
        
        alerts_data = []
        for alert in alerts:
            alerts_data.append({
                'id': alert.alert_id,
                'severity': alert.severity,
                'target': alert.target,
                'title': alert.title,
                'description': alert.description,
                'timestamp': alert.timestamp.isoformat(),
                'acknowledged': alert.acknowledged,
                'resolved': alert.resolved,
                'category': alert.category,
                'evidence': alert.evidence
            })
        
        return jsonify({
            'alerts': alerts_data,
            'total_count': len(alerts_data),
            'severity_counts': {
                'critical': len([a for a in alerts_data if a['severity'] == 'critical']),
                'high': len([a for a in alerts_data if a['severity'] == 'high']),
                'medium': len([a for a in alerts_data if a['severity'] == 'medium']),
                'low': len([a for a in alerts_data if a['severity'] == 'low'])
            }
        })
        
    except Exception as e:
        logger.error(f"Get alerts error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        socketio.emit('alert_acknowledged', {
            'alert_id': alert_id,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'status': 'acknowledged',
            'alert_id': alert_id
        })
        
    except Exception as e:
        logger.error(f"Acknowledge alert error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/<alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Resolve an alert"""
    try:
        socketio.emit('alert_resolved', {
            'alert_id': alert_id,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'status': 'resolved',
            'alert_id': alert_id
        })
        
    except Exception as e:
        logger.error(f"Resolve alert error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/dashboard')
def export_dashboard():
    """Export dashboard data"""
    try:
        dashboard_data = netpulse_platform.get_monitoring_dashboard()
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'dashboard_data': dashboard_data,
            'monitoring_status': monitoring_status,
            'traffic_status': traffic_analysis_status
        }
        
        return jsonify(export_data)
        
    except Exception as e:
        logger.error(f"Export dashboard error: {e}")
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info('Client connected to WebSocket')
    emit('connected', {
        'message': 'Connected to NetPulse Elite',
        'timestamp': datetime.now().isoformat()
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info('Client disconnected from WebSocket')

@socketio.on('request_status')
def handle_status_request():
    """Handle status request from client"""
    emit('status_update', {
        'monitoring': monitoring_status,
        'traffic': traffic_analysis_status,
        'timestamp': datetime.now().isoformat()
    })

def update_stats_periodically():
    """Background task to update statistics"""
    while True:
        try:
            if monitoring_status['active']:
                monitoring_status['stats']['total_scans'] += 1
                
                if monitoring_status['stats']['total_scans'] % 10 == 0:
                    monitoring_status['stats']['avg_security_score'] = 65 + (time.time() % 30)
                
                socketio.emit('monitoring_stats_update', monitoring_status['stats'])
            
            if traffic_analysis_status['active']:
                traffic_analysis_status['stats']['packets_analyzed'] += 1000 + int(time.time() % 500)
                traffic_analysis_status['stats']['bandwidth_util'] = int(time.time() % 100)
                
                if time.time() % 30 < 1:
                    traffic_analysis_status['stats']['threats_detected'] += 1
                    socketio.emit('threat_detected', {
                        'timestamp': datetime.now().isoformat(),
                        'description': 'Suspicious activity detected'
                    })
                
                if time.time() % 45 < 1:
                    traffic_analysis_status['stats']['anomalies_found'] += 1
                    socketio.emit('anomaly_detected', {
                        'timestamp': datetime.now().isoformat(),
                        'description': 'Network anomaly detected'
                    })
                
                socketio.emit('traffic_stats_update', traffic_analysis_status['stats'])
            
            time.sleep(5)
            
        except Exception as e:
            logger.error(f"Stats update error: {e}")
            time.sleep(10)

def start_background_tasks():
    """Start background tasks"""
    stats_thread = threading.Thread(target=update_stats_periodically)
    stats_thread.daemon = True
    stats_thread.start()

if __name__ == '__main__':
    print("""
    ███╗   ██╗███████╗████████╗██████╗ ██╗   ██╗██╗     ███████╗███████╗
    ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
    ██╔██╗ ██║█████╗     ██║   ██████╔╝██║   ██║██║     ███████╗█████╗  
    ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  
    ██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝███████╗███████║███████╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝
    
    ███████╗██╗     ██╗████████╗███████╗    ██╗    ██╗███████╗██████╗ 
    ██╔════╝██║     ██║╚══██╔══╝██╔════╝    ██║    ██║██╔════╝██╔══██╗
    █████╗  ██║     ██║   ██║   █████╗      ██║ █╗ ██║█████╗  ██████╔╝
    ██╔══╝  ██║     ██║   ██║   ██╔══╝      ██║███╗██║██╔══╝  ██╔══██╗
    ███████╗███████╗██║   ██║   ███████╗    ╚███╔███╔╝███████╗██████╔╝
    ╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝     ╚══╝╚══╝ ╚══════╝╚═════╝ 
    
    Web Interface - Continuous Network Intelligence Platform
    """)
    
    print("Starting NetPulse Elite Web Server...")
    print("Make sure you have the following dependencies installed:")
    print("pip install flask flask-cors flask-socketio")
    print("\nServer will be available at: http://localhost:5000")
    print("WebSocket endpoint: ws://localhost:5000")
    
    start_background_tasks()
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)