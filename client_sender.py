import argparse
import random
import time
import json
import socket
import requests
import sys

try:
    import socketio
except Exception:
    socketio = None


def random_event():
    protocol = random.choice(['TCP', 'UDP', 'ICMP'])
    return {
        'src_ip': f'192.168.1.{random.randint(1,254)}',
        'dst_ip': f'10.0.0.{random.randint(1,254)}',
        'protocol': protocol,
        'packets': random.randint(1,2000),
        'bytes': random.randint(40,200000),
        'duration': round(random.random()*60,2),
        'failed_logins': random.randint(0,10)
    }


def ddos_event():
    return {
        'src_ip': f'192.168.1.{random.randint(1,254)}',
        'dst_ip': f'10.0.0.{random.randint(1,254)}',
        'protocol': 'TCP',
        'packets': random.randint(5000,20000),
        'bytes': random.randint(1000000,5000000),
        'duration': round(random.random()*10,2),
        'failed_logins': 0
    }


def bruteforce_event():
    return {
        'src_ip': f'192.168.1.{random.randint(1,254)}',
        'dst_ip': f'10.0.0.{random.randint(1,254)}',
        'protocol': 'TCP',
        'packets': random.randint(1,50),
        'bytes': random.randint(40,5000),
        'duration': round(random.random()*5,2),
        'failed_logins': random.randint(6,30)
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server-ip', required=True)
    parser.add_argument('--port', type=int, default=5001)
    parser.add_argument('--mode', choices=['socketio','http'], default='socketio')
    parser.add_argument('--rate', type=float, default=1.0, help='events per second')
    parser.add_argument('--attack', choices=['none','ddos','bruteforce'], default='none')
    args = parser.parse_args()

    url = f'http://{args.server_ip}:{args.port}/ingest'

    if args.mode == 'socketio' and socketio is None:
        print('python-socketio is required for socketio mode. Falling back to http')
        args.mode = 'http'

    sio = None
    if args.mode == 'socketio':
        sio = socketio.Client()
        try:
            sio.connect(f'http://{args.server_ip}:{args.port}', namespaces=['/ingest'])
            print('Connected to server via Socket.IO')
        except Exception as e:
            print('Socket.IO connection failed, falling back to HTTP:', e)
            args.mode = 'http'

    try:
        while True:
            if args.attack == 'ddos':
                evt = ddos_event()
            elif args.attack == 'bruteforce':
                evt = bruteforce_event()
            else:
                evt = random_event()

            if args.mode == 'socketio' and sio is not None and sio.connected:
                try:
                    sio.emit('network_event', evt, namespace='/ingest')
                except Exception as e:
                    print('Socket emit failed, switching to HTTP', e)
                    args.mode = 'http'

            if args.mode == 'http':
                try:
                    r = requests.post(url, json=evt, timeout=3)
                    if r.status_code >= 400:
                        print('Server returned', r.status_code, r.text)
                except Exception as e:
                    print('HTTP send failed:', e)

            time.sleep(max(0.001, 1.0/args.rate))

    except KeyboardInterrupt:
        print('Stopped')
        if sio:
            try:
                sio.disconnect()
            except Exception:
                pass


if __name__ == '__main__':
    main()
