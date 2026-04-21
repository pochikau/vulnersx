import os
import json
import subprocess
import re
import time
import threading
import csv
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from sqlalchemy import desc, asc
import schedule
import logging

load_dotenv()

app = Flask(__name__, static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vuln_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_AS_ASCII'] = False

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

db = SQLAlchemy(app)


# Модели базы данных
class Vulnerability(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(500))
    software = db.Column(db.String(200))
    description = db.Column(db.Text)
    cvss = db.Column(db.Float)
    severity = db.Column(db.String(20))
    status = db.Column(db.String(20), default='new')
    comment = db.Column(db.String(200))
    found_date = db.Column(db.DateTime, default=datetime.utcnow)

    priority = db.Column(db.String(20))
    exploits_available = db.Column(db.Boolean, default=False)
    epss = db.Column(db.String(20))
    kev = db.Column(db.Boolean, default=False)
    patch_available = db.Column(db.Boolean, default=False)
    pocs_available = db.Column(db.Boolean, default=False)
    nuclei_template = db.Column(db.Boolean, default=False)
    hackerone = db.Column(db.Boolean, default=False)
    vuln_age = db.Column(db.String(20))
    vuln_age_days = db.Column(db.Integer, default=0)  # Для сортировки
    exposure = db.Column(db.String(50))
    vendors = db.Column(db.String(200))
    products = db.Column(db.String(200))
    raw_output = db.Column(db.Text)


class SoftwareList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True)


class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    software = db.Column(db.String(200))
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    vulnerabilities_found = db.Column(db.Integer, default=0)
    status = db.Column(db.String(50))
    error_message = db.Column(db.Text)


class ScanSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    enabled = db.Column(db.Boolean, default=True)
    vuln_age_days = db.Column(db.Integer, default=190)
    last_scan = db.Column(db.DateTime)
    next_scan = db.Column(db.DateTime)


# Инициализация базы данных
def init_db():
    with app.app_context():
        db.create_all()
        # Создаем расписание если его нет
        if ScanSchedule.query.first() is None:
            schedule = ScanSchedule(enabled=True, vuln_age_days=190)
            db.session.add(schedule)
            db.session.commit()

        # Загружаем software.txt если он существует
        load_software_from_file()


def load_software_from_file():
    """Загрузка ПО из файла software.txt"""
    software_file = Path('software.txt')
    if software_file.exists():
        with open(software_file, 'r', encoding='utf-8') as f:
            for line in f:
                name = line.strip().strip('"')
                if name and not SoftwareList.query.filter_by(name=name).first():
                    software = SoftwareList(name=name)
                    db.session.add(software)
        db.session.commit()
        return True
    return False


def age_to_days(age_str):
    """Преобразование строки возраста в дни"""
    if not age_str or age_str == 'Unknown':
        return 0
    if 'd' in age_str:
        return int(age_str.replace('d', ''))
    elif 'y' in age_str:
        return int(age_str.replace('y', '')) * 365
    elif 'm' in age_str:
        return int(age_str.replace('m', '')) * 30
    return 0


def scan_vulnerabilities(software_name, vuln_age_days=190):
    """Запуск поиска уязвимостей для конкретного ПО"""
    cmd = [
        "vulnx", "search", f'"{software_name}"',
        "--severity", "critical,high",
        "--vuln-age", f"<{vuln_age_days}",
        "--limit", "100"
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=300
        )
        return result.stdout, None
    except subprocess.CalledProcessError as e:
        return None, f"Ошибка при выполнении команды: {e}\n{e.stderr}"
    except subprocess.TimeoutExpired:
        return None, "Таймаут выполнения команды"
    except Exception as e:
        return None, str(e)


def parse_vulnx_output(output, software_name):
    """Парсинг вывода vulnx с сохранением полной информации"""
    vulnerabilities = []
    lines = output.split('\n')

    current_vuln = {}
    raw_lines = []

    for i, line in enumerate(lines):
        line = line.rstrip()
        raw_lines.append(line)

        cve_match = re.search(r'\[(CVE-\d{4}-\d+)\]', line)
        if cve_match:
            if current_vuln and 'id' in current_vuln:
                current_vuln['raw_output'] = '\n'.join(raw_lines)
                vulnerabilities.append(current_vuln)
                raw_lines = []

            cve_id = cve_match.group(1)

            severity_match = re.search(r'\]\s*(\w+)\s*-\s*(.+?)(?:\s*-|$)', line)
            if severity_match:
                severity = severity_match.group(1)
                description = severity_match.group(2).strip()
            else:
                severity = "Unknown"
                desc_parts = line.split(']')
                description = desc_parts[1].strip() if len(desc_parts) > 1 else "No description"

            current_vuln = {
                'id': cve_id,
                'name': description,
                'software': software_name,
                'description': description,
                'severity': severity,
                'cvss': 0.0,
                'priority': 'MEDIUM',
                'exploits_available': False,
                'epss': '0.0000',
                'kev': False,
                'patch_available': False,
                'pocs_available': False,
                'nuclei_template': False,
                'hackerone': False,
                'vuln_age': 'Unknown',
                'vuln_age_days': 0,
                'exposure': 'Unknown',
                'vendors': '',
                'products': '',
                'raw_output': ''
            }

        elif '↳' in line and current_vuln:
            if 'Priority:' in line:
                priority_match = re.search(r'Priority:\s*(\w+)', line)
                if priority_match:
                    current_vuln['priority'] = priority_match.group(1)

                current_vuln['exploits_available'] = 'EXPLOITS AVAILABLE' in line

                age_match = re.search(r'Vuln Age:\s*([\d\w]+)', line)
                if age_match:
                    age_str = age_match.group(1)
                    current_vuln['vuln_age'] = age_str
                    current_vuln['vuln_age_days'] = age_to_days(age_str)

            elif 'CVSS:' in line:
                cvss_match = re.search(r'CVSS:\s*([\d.]+)', line)
                if cvss_match:
                    current_vuln['cvss'] = float(cvss_match.group(1))

                epss_match = re.search(r'EPSS:\s*([\d.]+)', line)
                if epss_match:
                    current_vuln['epss'] = epss_match.group(1)

                current_vuln['kev'] = 'KEV: ✔' in line

            elif 'Exposure:' in line:
                exposure_match = re.search(r'Exposure:\s*([^|]+)', line)
                if exposure_match:
                    current_vuln['exposure'] = exposure_match.group(1).strip()

                vendors_match = re.search(r'Vendors:\s*([^|]+)', line)
                if vendors_match:
                    current_vuln['vendors'] = vendors_match.group(1).strip()

                products_match = re.search(r'Products:\s*(.+)$', line)
                if products_match:
                    current_vuln['products'] = products_match.group(1).strip()

            elif 'Patch:' in line:
                current_vuln['patch_available'] = '✔' in line
                current_vuln['pocs_available'] = 'POCs: ✔' in line
                current_vuln['nuclei_template'] = 'Nuclei Template: ✔' in line
                current_vuln['hackerone'] = 'HackerOne: ✔' in line

    if current_vuln and 'id' in current_vuln:
        current_vuln['raw_output'] = '\n'.join(raw_lines)
        vulnerabilities.append(current_vuln)

    return vulnerabilities


def save_vulnerabilities(vulnerabilities):
    """Сохранение уязвимостей в БД"""
    new_count = 0
    for vuln_data in vulnerabilities:
        existing = Vulnerability.query.get(vuln_data['id'])
        if not existing:
            vuln = Vulnerability(**vuln_data)
            db.session.add(vuln)
            new_count += 1
        else:
            # Обновляем существующую
            for key, value in vuln_data.items():
                if key not in ['id', 'found_date', 'status', 'comment']:
                    setattr(existing, key, value)

    db.session.commit()
    return new_count


def scan_all_software(vuln_age_days=None):
    """Сканирование всего ПО из списка"""
    if vuln_age_days is None:
        schedule_config = ScanSchedule.query.first()
        vuln_age_days = schedule_config.vuln_age_days if schedule_config else 190

    with app.app_context():
        software_list = SoftwareList.query.all()
        results = []
        total_new = 0

        for software in software_list:
            logger.info(f"Scanning {software.name}...")

            scan_log = ScanLog(
                software=software.name,
                status='running'
            )
            db.session.add(scan_log)
            db.session.commit()

            try:
                output, error = scan_vulnerabilities(software.name, vuln_age_days)

                if error:
                    scan_log.status = 'failed'
                    scan_log.error_message = error
                    results.append({'software': software.name, 'success': False, 'error': error})
                else:
                    vulns = parse_vulnx_output(output, software.name)
                    new_count = save_vulnerabilities(vulns)
                    total_new += new_count

                    scan_log.status = 'completed'
                    scan_log.vulnerabilities_found = new_count
                    results.append({
                        'software': software.name,
                        'success': True,
                        'new': new_count,
                        'total': len(vulns)
                    })

            except Exception as e:
                scan_log.status = 'failed'
                scan_log.error_message = str(e)
                results.append({'software': software.name, 'success': False, 'error': str(e)})

            db.session.commit()
            time.sleep(2)

        # Обновляем время последнего сканирования в расписании
        schedule_config = ScanSchedule.query.first()
        if schedule_config:
            schedule_config.last_scan = datetime.utcnow()
            schedule_config.next_scan = datetime.utcnow() + timedelta(days=1)
            db.session.commit()

        return results, total_new


def scheduled_scan():
    """Функция для запуска по расписанию"""
    schedule_config = ScanSchedule.query.first()
    if schedule_config and schedule_config.enabled:
        logger.info("Starting scheduled scan...")
        results, total_new = scan_all_software()
        logger.info(f"Scheduled scan completed. Found {total_new} new vulnerabilities.")

        # Отправка уведомления (можно добавить email или webhook)


def start_scheduler():
    """Запуск планировщика"""
    # Запускаем сканирование раз в сутки в 3:00
    schedule.every().day.at("03:00").do(scheduled_scan)

    while True:
        schedule.run_pending()
        time.sleep(60)


# Маршруты Flask
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)


@app.route('/api/software/upload', methods=['POST'])
def upload_software_file():
    """Загрузка файла software.txt"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400

    if file and file.filename.endswith('.txt'):
        file.save('software.txt')

        SoftwareList.query.delete()
        success = load_software_from_file()

        if success:
            return jsonify({'success': True, 'message': 'Software list updated successfully'})
        else:
            return jsonify({'success': False, 'message': 'Failed to parse software file'}), 400

    return jsonify({'success': False, 'message': 'Invalid file format'}), 400


@app.route('/api/software', methods=['GET'])
def get_software():
    software_list = SoftwareList.query.order_by(SoftwareList.name).all()
    return jsonify([s.name for s in software_list])


@app.route('/api/software', methods=['POST'])
def add_software():
    data = request.json
    name = data.get('name', '').strip()

    if not name:
        return jsonify({'success': False, 'message': 'Software name required'}), 400

    existing = SoftwareList.query.filter_by(name=name).first()
    if existing:
        return jsonify({'success': False, 'message': 'Software already exists'}), 400

    software = SoftwareList(name=name)
    db.session.add(software)
    db.session.commit()

    try:
        with open('software.txt', 'a', encoding='utf-8') as f:
            f.write(f'"{name}"\n')
    except Exception as e:
        logger.error(f"Error writing to software.txt: {e}")

    return jsonify({'success': True, 'message': 'Software added'})


@app.route('/api/software/<path:name>', methods=['DELETE'])
def delete_software(name):
    software = SoftwareList.query.filter_by(name=name).first()
    if software:
        db.session.delete(software)
        db.session.commit()

        try:
            with open('software.txt', 'r', encoding='utf-8') as f:
                lines = f.readlines()
            with open('software.txt', 'w', encoding='utf-8') as f:
                for line in lines:
                    if line.strip().strip('"') != name:
                        f.write(line)
        except Exception as e:
            logger.error(f"Error updating software.txt: {e}")

        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Software not found'}), 404


@app.route('/api/schedule', methods=['GET'])
def get_schedule():
    """Получение настроек расписания"""
    schedule_config = ScanSchedule.query.first()
    if schedule_config:
        return jsonify({
            'enabled': schedule_config.enabled,
            'vuln_age_days': schedule_config.vuln_age_days,
            'last_scan': schedule_config.last_scan.isoformat() if schedule_config.last_scan else None,
            'next_scan': schedule_config.next_scan.isoformat() if schedule_config.next_scan else None
        })
    return jsonify({'enabled': False, 'vuln_age_days': 190})


@app.route('/api/schedule', methods=['PUT'])
def update_schedule():
    """Обновление настроек расписания"""
    data = request.json
    schedule_config = ScanSchedule.query.first()

    if schedule_config:
        if 'enabled' in data:
            schedule_config.enabled = data['enabled']
        if 'vuln_age_days' in data:
            schedule_config.vuln_age_days = data['vuln_age_days']

        db.session.commit()
        return jsonify({'success': True})

    return jsonify({'error': 'Schedule not found'}), 404


@app.route('/api/scan', methods=['POST'])
def scan_software():
    data = request.json
    software_name = data.get('software')
    vuln_age_days = data.get('vuln_age_days', 190)

    if not software_name:
        return jsonify({'error': 'Software name required'}), 400

    try:
        logger.info(f"Starting scan for {software_name} with age limit {vuln_age_days} days")

        scan_log = ScanLog(
            software=software_name,
            status='running'
        )
        db.session.add(scan_log)
        db.session.commit()

        output, error = scan_vulnerabilities(software_name, vuln_age_days)

        if error:
            scan_log.status = 'failed'
            scan_log.error_message = error
            db.session.commit()
            return jsonify({'error': error}), 500

        vulns = parse_vulnx_output(output, software_name)
        new_count = save_vulnerabilities(vulns)

        scan_log.status = 'completed'
        scan_log.vulnerabilities_found = new_count
        db.session.commit()

        return jsonify({
            'success': True,
            'new_vulnerabilities': new_count,
            'total': len(vulns),
            'software': software_name
        })

    except Exception as e:
        logger.error(f"Scan error: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/all', methods=['POST'])
def scan_all():
    """Запуск сканирования всего ПО"""
    data = request.json or {}
    vuln_age_days = data.get('vuln_age_days')

    try:
        # Запускаем в отдельном потоке
        def scan_thread():
            results, total_new = scan_all_software(vuln_age_days)
            logger.info(f"Scan completed. Found {total_new} new vulnerabilities.")

        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()

        return jsonify({
            'success': True,
            'message': 'Scan started for all software'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    software = request.args.get('software')
    status = request.args.get('status')
    severity = request.args.get('severity')
    sort_by = request.args.get('sort_by', 'found_date')
    sort_order = request.args.get('sort_order', 'desc')

    query = Vulnerability.query

    if software:
        query = query.filter_by(software=software)
    if status:
        query = query.filter_by(status=status)
    if severity:
        query = query.filter_by(severity=severity)

    # Сортировка
    if sort_by == 'vuln_age':
        # Сортировка по возрасту (по дням)
        if sort_order == 'desc':
            query = query.order_by(desc(Vulnerability.vuln_age_days))
        else:
            query = query.order_by(asc(Vulnerability.vuln_age_days))
    elif sort_by == 'severity':
        # Сортировка по критичности
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        all_vulns = query.all()
        all_vulns.sort(key=lambda x: severity_order.get(x.severity, 0), reverse=(sort_order == 'desc'))
        return jsonify([format_vuln(v) for v in all_vulns])
    else:
        if sort_order == 'desc':
            query = query.order_by(desc(getattr(Vulnerability, sort_by, Vulnerability.found_date)))
        else:
            query = query.order_by(asc(getattr(Vulnerability, sort_by, Vulnerability.found_date)))

    vulns = query.all()
    return jsonify([format_vuln(v) for v in vulns])


@app.route('/api/vulnerabilities/export', methods=['GET'])
def export_vulnerabilities():
    """Экспорт уязвимостей в CSV"""
    software = request.args.get('software')
    status = request.args.get('status')
    severity = request.args.get('severity')

    query = Vulnerability.query

    if software:
        query = query.filter_by(software=software)
    if status:
        query = query.filter_by(status=status)
    if severity:
        query = query.filter_by(severity=severity)

    vulns = query.order_by(Vulnerability.found_date.desc()).all()

    # Создаем CSV
    output = []
    output.append(['CVE ID', 'Name', 'Software', 'CVSS', 'Severity', 'Status',
                   'Priority', 'Exploits', 'EPSS', 'KEV', 'Patch', 'Vuln Age',
                   'Found Date', 'Comment'])

    for v in vulns:
        output.append([
            v.id,
            v.name,
            v.software,
            v.cvss,
            v.severity,
            v.status,
            v.priority,
            'Yes' if v.exploits_available else 'No',
            v.epss,
            'Yes' if v.kev else 'No',
            'Yes' if v.patch_available else 'No',
            v.vuln_age,
            v.found_date.strftime('%Y-%m-%d %H:%M:%S') if v.found_date else '',
            v.comment or ''
        ])

    # Сохраняем во временный файл
    filename = f"vuln_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = Path('/tmp') / filename

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(output)

    return send_file(filepath, as_attachment=True, download_name=filename)


def format_vuln(v):
    """Форматирование уязвимости для JSON"""
    one_day_ago = datetime.utcnow() - timedelta(days=1)

    return {
        'id': v.id,
        'name': v.name,
        'software': v.software,
        'description': v.description,
        'cvss': v.cvss,
        'severity': v.severity,
        'status': v.status,
        'comment': v.comment,
        'found_date': v.found_date.isoformat() if v.found_date else None,
        'priority': v.priority,
        'exploits_available': v.exploits_available,
        'epss': v.epss,
        'kev': v.kev,
        'patch_available': v.patch_available,
        'pocs_available': v.pocs_available,
        'nuclei_template': v.nuclei_template,
        'hackerone': v.hackerone,
        'vuln_age': v.vuln_age,
        'vuln_age_days': v.vuln_age_days,
        'exposure': v.exposure,
        'vendors': v.vendors,
        'products': v.products,
        'raw_output': v.raw_output,
        'is_new': v.status == 'new' or (v.found_date and v.found_date > one_day_ago)
    }


@app.route('/api/vulnerabilities/<cve_id>', methods=['PUT'])
def update_vulnerability(cve_id):
    data = request.json
    vuln = Vulnerability.query.get(cve_id)

    if vuln:
        if 'status' in data:
            vuln.status = data['status']
        if 'comment' in data:
            vuln.comment = data['comment']

        db.session.commit()
        return jsonify({'success': True})

    return jsonify({'error': 'Vulnerability not found'}), 404


@app.route('/api/stats', methods=['GET'])
def get_stats():
    total = Vulnerability.query.count()
    new = Vulnerability.query.filter_by(status='new').count()
    in_progress = Vulnerability.query.filter_by(status='in_progress').count()
    closed = Vulnerability.query.filter_by(status='closed').count()

    critical = Vulnerability.query.filter(Vulnerability.cvss >= 9.0).count()
    high = Vulnerability.query.filter(Vulnerability.cvss.between(7.0, 8.9)).count()
    with_exploits = Vulnerability.query.filter_by(exploits_available=True).count()

    software_stats = db.session.query(
        Vulnerability.software,
        db.func.count(Vulnerability.id)
    ).group_by(Vulnerability.software).all()

    schedule_config = ScanSchedule.query.first()

    return jsonify({
        'total': total,
        'new': new,
        'in_progress': in_progress,
        'closed': closed,
        'critical': critical,
        'high': high,
        'with_exploits': with_exploits,
        'by_software': dict(software_stats),
        'schedule': {
            'enabled': schedule_config.enabled if schedule_config else False,
            'vuln_age_days': schedule_config.vuln_age_days if schedule_config else 190,
            'last_scan': schedule_config.last_scan.isoformat() if schedule_config and schedule_config.last_scan else None
        }
    })


if __name__ == '__main__':
    init_db()

    # Запускаем планировщик в отдельном потоке
    scheduler_thread = threading.Thread(target=start_scheduler, daemon=True)
    scheduler_thread.start()
    logger.info("Scheduler started")

    import sys

    use_ssl = '--ssl' in sys.argv

    if use_ssl and os.path.exists('/app/ssl/cert.pem') and os.path.exists('/app/ssl/key.pem'):
        logger.info(f"Starting HTTPS server on port 443")
        context = ('/app/ssl/cert.pem', '/app/ssl/key.pem')
        app.run(host='0.0.0.0', port=443, ssl_context=context, debug=False)
    else:
        logger.info(f"Starting HTTP server on port 80")
        app.run(host='0.0.0.0', port=80, debug=False)