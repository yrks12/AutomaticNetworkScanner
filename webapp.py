import schedule
import threading
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import re
import subprocess
import smtplib
from datetime import datetime
import time

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
db = SQLAlchemy(app)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(50), nullable=False)
    ports = db.Column(db.String(50), nullable=False)
    site_name = db.Column(db.String(50), nullable=True)
    last_scan_result = db.Column(db.String(500), nullable=True)
    last_scan_time = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='Pending')

def scan_network(address, ports):
    result = subprocess.check_output(f"sudo nmap -p {ports} {address}", shell=True)
    return result

def parse_nmap_output(output):
    lines = output.decode().split('\n')
    host_info = None
    for line in lines:
        match = re.match(r'Nmap scan report for (.+)', line)
        if match:
            host_info = match.group(1)
            break
    port_lines = lines[4:-3]
    open_ports = []
    for line in port_lines:
        port_match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(\w+)', line)
        if port_match:
            port_number = int(port_match.group(1))
            port_type = port_match.group(2)
            port_state = port_match.group(3)
            port_service = port_match.group(4)
            open_ports.append({'port': port_number, 'type': port_type, 'state': port_state, 'service': port_service})
    return host_info, {'host': host_info, 'ports': open_ports}

def send_email(site_name, subject, body):
    email_addr = "EMAIL"
    password = "PASSWORD"
    msg = f"Subject: Open Ports Found on {site_name} {subject} \n\n{body}."

    if body != "Non open ports are found":
        mail = smtplib.SMTP("smtp.gmail.com", 587)
        mail.starttls()
        mail.login(email_addr, password)
        mail.sendmail(email_addr, "y0533127296@gmail.com", msg.encode('utf-8'))
        mail.quit()

def email_body(scan_result):
    open_ports = ""
    for port in scan_result['ports']:
        if port['state'] == "open":
            open_ports += f"Port {port['port']} ({port['type']}) is open\n"

    if open_ports != "":
        return open_ports
    else:
        return "Non open ports are found"

def perform_scan(scan_id):
    scan = Scan.query.get(scan_id)
    scan.status = 'Running'
    db.session.commit()

    result = scan_network(scan.address, scan.ports)
    host, scan_result = parse_nmap_output(result)
    open_ports = email_body(scan_result)
    send_email(scan.site_name, host, open_ports)

    scan.last_scan_result = open_ports
    scan.last_scan_time = datetime.utcnow()
    scan.status = 'Completed'
    db.session.commit()

@app.route('/')
def home():
    scans = Scan.query.all()

    def mask_ip(ip):
        parts = ip.split('.')
        masked_ip = parts[0] + '.' + 'xxx.xxx.' + parts[-1]
        return masked_ip

    return render_template('index.html', scans=scans, mask_ip=mask_ip)

@app.route('/add_scan', methods=['POST'])
def add_scan():
    address = request.form.get('address')
    ports = request.form.get('ports')
    site_name = request.form.get('site_name')

    new_scan = Scan(address=address, ports=ports, site_name=site_name)
    db.session.add(new_scan)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/perform_scan/<int:scan_id>')
def trigger_scan(scan_id):
    perform_scan(scan_id)
    return redirect(url_for('home'))

@app.route('/remove_scan/<int:scan_id>', methods=['POST', 'DELETE'])
def remove_scan(scan_id):
    if request.method in ['POST', 'DELETE']:
        scan = Scan.query.get(scan_id)
        if scan:
            db.session.delete(scan)
            db.session.commit()
    return redirect(url_for('home'))

def schedule_scans():
    with app.app_context():
        scans = Scan.query.all()
        for scan in scans:
            perform_scan(scan.id)

schedule.every(1).week.do(schedule_scans)

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        existing_scans = Scan.query.all()

        if existing_scans:
            for scan in existing_scans:
                perform_scan(scan.id)

    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.start()

    app.run(debug=False, host="0.0.0.0", port=3030)
