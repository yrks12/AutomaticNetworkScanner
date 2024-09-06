# AutomaticNetworkScanner

AutomaticNetworkScanner is a Python-based web application that automates network scanning using `nmap`, schedules regular scans, and sends email notifications for any detected open ports. The tool provides an easy-to-use web interface for managing scan tasks and viewing scan results. It is ideal for system administrators who want to automate network security checks.

## Features

- **Automated Network Scans**: Uses `nmap` to scan IP addresses or domain names for open ports.
- **Scheduling**: Automatically schedules network scans on a weekly basis (configurable).
- **Email Alerts**: Sends email notifications when open ports are detected.
- **Web Interface**: A simple and intuitive web interface to manage scans, view results, and add new scan tasks.
- **Result History**: Stores scan results in a SQLite database, allowing users to review past scans.

## Technologies Used

- **Flask**: A lightweight web framework for creating the user interface and managing routes.
- **SQLAlchemy**: ORM (Object-Relational Mapping) tool for handling the SQLite database where scan tasks and results are stored.
- **nmap**: A network scanning tool to detect open ports.
- **schedule**: A Python library to manage the scheduling of scan tasks.
- **smtplib**: Python's built-in library for sending email notifications.

## Project Structure

```
.
├── webapp.py               # Main Flask app
├── templates/
│   └── index.html          # Template for the homepage
├── scans.db                # SQLite database for storing scan tasks
├── README.md               # Project documentation
└── requirements.txt        # Python dependencies
```

## Prerequisites

- **Python 3.x**
- **nmap** (must be installed and accessible via `sudo`)
- **Flask** and **SQLAlchemy** for the web interface and database handling.
- **SMTP server credentials** to send email notifications.

### Installing Python Dependencies

You can install the required Python libraries using `pip`:

```bash
pip install -r requirements.txt
```

### Installing nmap

Ensure `nmap` is installed on your system:

```bash
# For Linux
sudo apt-get install nmap

# For macOS
brew install nmap
```

## Getting Started

### 1. Configure Email

In `webapp.py`, update the `send_email()` function with your email credentials to enable email notifications for scan results:

```python
email_addr = "your_email@gmail.com"
password = "your_password"
```

Make sure your email provider allows you to send emails via SMTP. For Gmail, you might need to enable "Less secure apps" in your account settings.

### 2. Running the Application

To start the Flask application:

```bash
python webapp.py
```

By default, the app runs on `http://0.0.0.0:3030`. Open a web browser and navigate to this address.

### 3. Adding a Network Scan

1. Visit the homepage at `http://localhost:3030`.
2. Enter the target IP address or domain, the ports to scan (e.g., `22, 80, 443`), and an optional site name.
3. Click "Submit" to add the scan. The scan will run automatically based on the scheduling configuration.

### 4. Scheduling

By default, the scans are scheduled to run weekly. You can modify the scan frequency in the `schedule_scans()` function in `webapp.py`. To change the schedule:

```python
# Run the scans daily at a specific time
schedule.every().day.at("14:00").do(schedule_scans)
```

### 5. Manual Scan

To manually trigger a scan, visit:

```
http://localhost:3030/perform_scan/<scan_id>
```

Replace `<scan_id>` with the ID of the scan task you want to run.

### 6. Viewing Scan Results

The homepage displays all the previously scheduled scans with details such as the IP address, ports, and the results of the last scan. Open ports, if any, are shown, and emails are sent if open ports are detected.

## Key Functions

### `scan_network(address, ports)`
Executes the `nmap` command to scan the specified address and ports, returning the result.

### `parse_nmap_output(output)`
Parses the raw `nmap` output to extract information about the host and the detected open ports.

### `send_email(site_name, subject, body)`
Sends an email notification with the results of the scan. Alerts are sent only if open ports are detected.

### `perform_scan(scan_id)`
Runs a scan for the specified `scan_id`, updates the database with the results, and sends an email if any open ports are found.

### `schedule_scans()`
Schedules scans for all entries in the database to run on a weekly basis (or as configured).

### `run_scheduler()`
Runs the scan scheduler in a separate thread, ensuring scans are executed at the scheduled times.

## Customization

### Modify Scan Frequency

By default, scans are scheduled to run weekly. To change the scan frequency, modify the scheduling logic in `schedule_scans()`:

```python
# Example: run scans every day at 2 PM
schedule.every().day.at("14:00").do(schedule_scans)
```

### Add More Ports or IP Ranges

To scan additional ports or modify the scan configuration, update the form in `index.html` or adjust the `ports` field when adding a new scan task.

## Troubleshooting

### Common Issues

1. **Email Not Sending**: Ensure your email credentials are correct and that your email provider allows SMTP access. For Gmail, enable "Less secure apps" in your account settings.
2. **nmap Not Found**: Ensure `nmap` is installed and available on your system. Test by running `sudo nmap --version`.
3. **Scheduler Not Running**: Ensure the scheduler thread is started correctly when the app initializes. It should be running in the background to trigger scans at scheduled times.

## Contributing

Contributions are welcome! Feel free to open issues, submit pull requests, or suggest new features for this project.
