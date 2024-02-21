from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import re
import subprocess
import smtplib
import schedule
import time
from datetime import datetime

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


# Function to scan the network
def scan_network(address, ports):
    result = subprocess.check_output(f"sudo nmap -p {ports} {address}", shell=True)
    return result


# Function to parse Nmap output
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


# Function to send email
def send_email(site_name, subject, body):
    email_addr = "y0533127296@gmail.com"
    password = "rplhgxrbsxndspnj"
    msg = f"Subject: Open Ports Found on {site_name} {subject} \n\n{body}."
    if body != "Non open ports are found":
        mail = smtplib.SMTP("smtp.gmail.com", 587)
        mail.starttls()
        mail.login(email_addr, password)
        mail.sendmail(email_addr,"sam@yessecurity.eu", msg)
        mail.quit()


# make the body for sending the email
def email_body(scan_result):
    open_ports = ""
    for port in scan_result['ports']:
        if port['state'] == "open":
            open_ports += f"Port {port['port']} ({port['type']}) is open\n"

    if open_ports != "":
        return open_ports
    else:
        return "Non open ports are found"


# Function to perform the scan and update the database
def perform_scan(scan_id):
    scan = Scan.query.get(scan_id)
    result = scan_network(scan.address, scan.ports)
    host, scan_result = parse_nmap_output(result)
    open_ports = email_body(scan_result)
    send_email(scan.site_name,host, open_ports)

    scan.last_scan_result = open_ports
    scan.last_scan_time = datetime.utcnow()
    db.session.commit()



# Function to schedule the scans
def schedule_scans():
    scans = Scan.query.all()
    for scan in scans:
        print("[+] running ")
        perform_scan(scan.id)


# Schedule the scans to run every week
schedule.every(1).week.do(schedule_scans)


# Run the scheduler in a separate thread
def run_scheduler():
    with app.app_context():
        while True:
            schedule.run_pending()
            time.sleep(1)


# Route for the home page
@app.route('/')
def home():
    scans = Scan.query.all()

    def mask_ip(ip):
        parts = ip.split('.')
        masked_ip = parts[0] + '.' + 'xxx.xxx.' + parts[-1]
        return masked_ip

    return render_template('index.html', scans=scans, mask_ip=mask_ip)


# Route for adding a new scan
@app.route('/add_scan', methods=['POST'])
def add_scan():
    address = request.form.get('address')
    ports = request.form.get('ports')
    site_name = request.form.get('site_name')

    new_scan = Scan(address=address, ports=ports, site_name=site_name)  # Modify this line
    db.session.add(new_scan)
    db.session.commit()
    return redirect(url_for('home'))


# Route for performing a scan
@app.route('/perform_scan/<int:scan_id>')
def trigger_scan(scan_id):
    perform_scan(scan_id)
    return redirect(url_for('home'))

# Route for removing a scan
@app.route('/remove_scan/<int:scan_id>', methods=['POST', 'DELETE'])
def remove_scan(scan_id):
    if request.method in ['POST', 'DELETE']:
        scan = Scan.query.get(scan_id)
        if scan:
            db.session.delete(scan)
            db.session.commit()
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    # Start the scheduler in a separate thread
    import threading

    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.start()

    app.run(debug=True)