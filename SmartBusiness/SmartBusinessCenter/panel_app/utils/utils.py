import matplotlib.pyplot as plt
import base64
from io import BytesIO
import ipaddress
from django.core.mail import send_mail
from panel_app.models import IncidentManagement
import datetime
from django.utils import timezone
from django.http import HttpResponse
import csv
import pytz
from django.db import transaction
from django.db.models import Q
import subprocess
import os
import pandas as pd
import socket
import requests

def send_email(title,message):
    try:
        send_mail(title,message,'paicc.alertas@gmail.com',['agimenox@gmail.com'], fail_silently=False)
    except:
        return False

def is_valid_ipv4_address(address):
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False
    

def initialize_graph_case():
    '''Funtion to graph bars charts'''
    open_cases = IncidentManagement.objects.filter(incident_state='Open').count()
    progress_cases = IncidentManagement.objects.filter(incident_state='Progress').count()

    fig = plt.figure(figsize=(4, 4))
    ax = fig.add_subplot(111)

    ax.bar(['Open', 'Progress'], [open_cases, progress_cases])

    ax.set_title('SOC Alerts Cases')
    ax.set_xlabel('Status')
    ax.set_ylabel('Number of Cases')
    chart_path = 'chart_cases_overview.png'
    fig.savefig('static/dashboards/' + chart_path, format='png')
    
def initialize_graph_month_case():
        
    # Define the start and end dates for the search range
    current_date = timezone.make_aware(datetime.datetime.now())
    start_date = current_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end_date = start_date.replace(month=start_date.month + 1) - datetime.timedelta(days=1)

    last_start_date, last_end_date = get_last_month_dates(current_date)

    last_start_date = datetime.datetime.strptime(last_start_date, '%Y-%m-%d')
    last_end_date = datetime.datetime.strptime(last_end_date, '%Y-%m-%d')
    # Retrieve all objects that match the query
    last_start_date = timezone.make_aware(last_start_date, pytz.timezone('America/Argentina/Buenos_Aires'))
    last_end_date = timezone.make_aware(last_end_date, pytz.timezone('America/Argentina/Buenos_Aires'))
    this_month_cases = IncidentManagement.objects.filter(registration_date__lte=end_date, registration_date__gte=start_date).count()
    last_month_cases = IncidentManagement.objects.filter(registration_date__lte=last_end_date, registration_date__gte=last_start_date).count()
    
    '''Funtion to graph bars charts'''

    fig = plt.figure(figsize=(4, 4))
    ax = fig.add_subplot(111)

    ax.bar(['Month Cases', 'Last Month Cases'], [this_month_cases, last_month_cases])

    ax.set_title('Month Cases')
    ax.set_xlabel('Status')
    chart_path = 'chart_cases_months.png'
    fig.savefig('static/dashboards/' + chart_path, format='png')

def get_csv(start_date,end_date):

    incidents = IncidentManagement.objects.filter(registration_date__gte=start_date,registration_date__lte=end_date)
    response = HttpResponse(content_type='text/csv')
    response['Content-Dispostion'] = 'attachment; filename=incidents_export.csv'
    writer = csv.writer(response)
    writer.writerow(['incident_number','review_operator','incident_state','registration_date','incident_comment'])
    incidents_fields = incidents.values_list('incident_number','review_operator','incident_state','registration_date','incident_comment')
    for incident in incidents_fields:
        writer.writerow(incident)
    return response


def get_last_month_dates(date):
    # Get the first day of the current month
    first_day = date.replace(day=1)
    # Subtract one day to get the last day of the previous month
    last_month_last_day = first_day - datetime.timedelta(days=1)
    # Subtract the number of days in the previous month to get the first day of the previous month
    last_month_first_day = last_month_last_day.replace(day=1)
    # Return the start and end dates of the previous month
    return (last_month_first_day.strftime('%Y-%m-%d'), last_month_last_day.strftime('%Y-%m-%d'))

def get_locked_accounts():

    locked_user_path = 'C:\Repo_GitHub\PAICenter\PaiControl\TestData\locked_accounts.csv'
    with open(locked_user_path, newline='') as csvfile:
        locked_users = csv.reader(csvfile, quotechar='|')
        next(locked_users)
        total_row = len(locked_users)
        return 
    

def time_to_response(incident_id):

    case_date = IncidentManagement.objects.filter(pk=incident_id).values('registration_date').first()['registration_date']
    date_now = timezone.make_aware(datetime.datetime.now())
    sla = date_now - case_date
    return sla
    

def initialize_open_cases_severity():
        

    # Retrieve all objects that match the query
    critical_cases = IncidentManagement.objects.filter(Q(incident_state='Open') | Q(incident_state='Progress'), case_priority='Critical').count()
    high_cases = IncidentManagement.objects.filter(Q(incident_state='Open') | Q(incident_state='Progress'), case_priority='High').count()
    medium_cases = IncidentManagement.objects.filter(Q(incident_state='Open') | Q(incident_state='Progress'), case_priority='Medium').count()
    low_cases = IncidentManagement.objects.filter(Q(incident_state='Open') | Q(incident_state='Progress'), case_priority='Low').count()

    fig = plt.figure(figsize=(4, 4))
    ax = fig.add_subplot(111)

    ax.bar(['Critical', 'High','Medium','Low'], [critical_cases, high_cases,medium_cases,low_cases])

    ax.set_title('Severity Cases')
    ax.set_xlabel('Status')
    ax.set_ylabel('Number of Cases')
    chart_path = 'chart_cases_severity.png'
    fig.savefig('static/dashboards/' + chart_path, format='png')

def load_data_from_scan():
    '''This read the output file from network scan and return to be showed in the template dashboard'''
    try:
        file = os.path.join(os.getcwd(), 'panel_app', 'static', 'network_scan_hostnames.txt') 
        with open(file, 'r') as f:
            df = f.readlines()
            return df
        
    except:
        return f'No Data'
    
def read_data_from_scan():
    '''This function load the outputdata and transform it to a dictionary'''
    file_path = os.path.join(os.getcwd(), 'panel_app', 'static', 'network_scan_hostnames.txt') 
    result = {}
    with open(file_path, 'r') as file:
        for line in file:
            ip, hostname = line.strip().split(',')
            result[ip] = hostname
    return result
    

def scan_network(firts_oct, second_oct,third_oct):
    net_to_scan = f'{firts_oct}.{second_oct}.{third_oct}.0'
    if is_valid_ipv4_address(net_to_scan):
        final_output_file = os.path.join(os.getcwd(), 'panel_app', 'static', 'network_scan_hostnames.txt')
        with open(final_output_file, 'w') as file:
            for i in range(1, 256):
                ip = f'{firts_oct}.{second_oct}.{third_oct}.{i}'  # Replace with the appropriate IP range
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    continue

                file.write(f'{ip},{hostname}\n')

def get_current_currency():
    api_url = "https://openexchangerates.org/api/latest.json?app_id=b78993fc7cd347dd85db096cfceee0c3"
    currency_data = requests.get(api_url)
    data = currency_data.json()
    return data["rates"]
    