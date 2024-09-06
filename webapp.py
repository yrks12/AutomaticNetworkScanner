import schedule
import threading
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import re
import subprocess
import smtplib
from datetime import datetime
import time

# Initialize Flask app and configure the SQLite database to store scan details
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
db = SQLAlchemy(app)

# Model representing a network scan entry in the database
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique scan ID
    address = db.Column(db.String(50), nullable=False)  # Target IP address or domain
    ports = db.Column(db.String(50), nullable=False)  # Ports to scan
    site_name = db.Column(db.String(50), nullable=True)  # Optional site name for reference
    last_scan_result = db.Column(db.String(500), nullable=True)  # Result of the last scan
    last_scan_time = db.Column(db.DateTime, nullable=True)  # Timestamp of the last scan
    status = db.Column(db.String(20), default='Pending')  # Status of the scan (Pending, Running, Completed)

# Function to execute a network scan using nmap
def scan_network(address, ports):
    # Run the nmap command to scan the specified address and ports, and return the result
    result = subprocess.check_output(f"sudo nmap -p {ports} {address}", shell=True)
    return result

# Function to parse the nmap output and extract host and port information
def parse_nmap_output(output):
    lines = output.decode().split('\n')  # Decode nmap output to process it line by line
    host_info = None
    for line in lines:
        match = re.match(r'Nmap scan report for (.+)', line)  # Match the host info line
        if match:
            host_info = match.group(1)  # Capture the host information
            break

    # Extract the port information from the output
    port_lines = lines[4:-3]  # Ports are typically listed between specific lines
    open_ports = []
    for line in port_lines:
        port_match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(\w+)', line)  # Match the port details
        if port_match:
            port_number = int(port_match.group(1))  # Port number
            port_type = port_match.group(2)  # Protocol type (TCP/UDP)
            port_state = port_match.group(3)  # State of the port (open, closed, etc.)
            port_service = port_match.group(4)  # Service running on the port
            open_ports.append({'port': port_number, 'type': port_type, 'state': port_state, 'service': port_service})
    
    # Return the parsed host and port information
    return host_info, {'host': host_info, 'ports': open_ports}

# Function to send an email with the scan results
def send_email(site_name, subject, body):
    # Credentials for sending the email
    email_addr = "EMAIL"
    password = "PASSWORD"
    msg = f"Subject: Open Ports Found on {site_name} {subject} \n\n{body}."

    # Only send an email if open ports are found
    if body != "Non open ports are found":
        mail = smtplib.SMTP("smtp.gmail.com", 587)  # Connect to Gmail SMTP server
        mail.starttls()  # Start TLS for security
        mail.login(email_addr, password)  # Log in with email and password
        mail.sendmail(email_addr, "email@example.com", msg.encode('utf-8'))  # Send the email
        mail.quit()  # Close the SMTP connection

# Function to format the email body with open port information
def email_body(scan_result):
    open_ports = ""
    # Construct the email body based on the open ports found
    for port in scan_result['ports']:
        if port['state'] == "open":  # Only include open ports
            open_ports += f"Port {port['port']} ({port['type']}) is open\n"

    if open_ports != "":
        return open_ports  # Return the list of open ports if any are found
    else:
        return "Non open ports are found"  # Return message if no open ports are found

# Function to perform a network scan and update the scan's status and result in the database
def perform_scan(scan_id):
    scan = Scan.query.get(scan_id)  # Retrieve the scan entry from the database by ID
    scan.status = 'Running'  # Update the scan status to "Running"
    db.session.commit()

    # Perform the network scan and parse the results
    result = scan_network(scan.address, scan.ports)
    host, scan_result = parse_nmap_output(result)
    open_ports = email_body(scan_result)
    
    # Send an email with the scan results
    send_email(scan.site_name, host, open_ports)

    # Update the scan entry with the result and the time the scan was completed
    scan.last_scan_result = open_ports
    scan.last_scan_time = datetime.utcnow()
    scan.status = 'Completed'  # Mark the scan as completed
    db.session.commit()

# Route for the homepage displaying all scans
@app.route('/')
def home():
    scans = Scan.query.all()  # Retrieve all scans from the database

    # Function to mask part of an IP address for privacy reasons
    def mask_ip(ip):
        parts = ip.split('.')
        masked_ip = parts[0] + '.' + 'xxx.xxx.' + parts[-1]  # Mask middle parts of the IP address
        return masked_ip

    # Render the homepage with the scans and masked IP addresses
    return render_template('index.html', scans=scans, mask_ip=mask_ip)

# Route for adding a new scan
@app.route('/add_scan', methods=['POST'])
def add_scan():
    address = request.form.get('address')  # Get the target address from the form
    ports = request.form.get('ports')  # Get the ports to scan from the form
    site_name = request.form.get('site_name')  # Get the site name (optional)

    # Create a new scan entry and add it to the database
    new_scan = Scan(address=address, ports=ports, site_name=site_name)
    db.session.add(new_scan)
    db.session.commit()
    return redirect(url_for('home'))  # Redirect back to the homepage after adding the scan

# Route for manually triggering a scan by scan ID
@app.route('/perform_scan/<int:scan_id>')
def trigger_scan(scan_id):
    perform_scan(scan_id)  # Perform the scan
    return redirect(url_for('home'))  # Redirect to the homepage after the scan

# Route for removing a scan from the database by scan ID
@app.route('/remove_scan/<int:scan_id>', methods=['POST', 'DELETE'])
def remove_scan(scan_id):
    if request.method in ['POST', 'DELETE']:
        scan = Scan.query.get(scan_id)  # Retrieve the scan from the database
        if scan:
            db.session.delete(scan)  # Delete the scan from the database
            db.session.commit()
    return redirect(url_for('home'))  # Redirect to the homepage after deletion

# Function to schedule scans for all entries in the database
def schedule_scans():
    with app.app_context():
        scans = Scan.query.all()  # Retrieve all scans from the database
        for scan in scans:
            perform_scan(scan.id)  # Perform each scan

# Schedule scans to run once a week
schedule.every(1).week.do(schedule_scans)

# Function to run the scheduler in a separate thread
def run_scheduler():
    while True:
        schedule.run_pending()  # Run any scheduled tasks
        time.sleep(1)  # Wait 1 second before checking again

# Main entry point of the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create the database tables if they don't exist yet
        existing_scans = Scan.query.all()  # Retrieve all existing scans

        # Perform an initial scan for all existing entries in the database
        if existing_scans:
            for scan in existing_scans:
                perform_scan(scan.id)

    # Start the scheduler in a separate thread
    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.start()

    # Start the Flask web application on host 0.0.0.0 and port 3030
    app.run(debug=False, host="0.0.0.0", port=3030)
