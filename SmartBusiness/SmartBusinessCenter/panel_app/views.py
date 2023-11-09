from django.shortcuts import render, redirect
from panel_app.models import FwAssign, CertAssign, MailGireAssign, IncidentManagement, CaseComment
from datetime import date
from panel_app.utils.virust_api import domain_report, ip_report, upload_file, consult_file_report
from django.views.generic import CreateView, ListView, DetailView, UpdateView, TemplateView
from django.urls import reverse, reverse_lazy
from panel_app.forms import IncidentMgmtForm
from django.http import HttpResponse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os
import urllib, base64
import csv
from panel_app.utils.utils import (
    is_valid_ipv4_address,
    send_email,
    initialize_graph_case,
    get_last_month_dates,
    initialize_graph_month_case,
    time_to_response,
    initialize_open_cases_severity,
    scan_network,
    read_data_from_scan,
    get_current_currency
                                   )
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
import datetime
from django.utils import timezone
from .forms import NumberForm
import requests
from django.views import View
import asyncio

def between_date_fw():
    datenow = date.today()
    context = FwAssign.objects.get(initial_date__lte=datenow, end_date__gte=datenow)
    return context


def between_date_cert():
    datenow = date.today()
    context = CertAssign.objects.get(initial_date__lte=datenow, end_date__gte=datenow)
    return context

def between_date_gire():
    datenow = date.today()
    context = MailGireAssign.objects.get(initial_date__lte=datenow, end_date__gte=datenow)
    return context

@login_required
def dashboard(request):

    #firewall_operator = between_date_fw
    #cert_operator = between_date_cert
    #gire_operator = between_date_gire
    initialize_graph_case()
    initialize_graph_month_case()
    initialize_open_cases_severity()
    last_scan = read_data_from_scan()

    return render(
    request=request,
    template_name='dashboard.html',
    context={'last_scan': last_scan }, )


@login_required
def search_domain(request):
    if request.method == "POST":
        data = request.POST
        searchs_result = domain_report(data['name_to_search'])

        dns_records = searchs_result['data']['attributes']['last_dns_records']
        txt_records = []
        a_records = []

        for dns in dns_records:
            if dns['type'] == 'TXT':
                txt_records.append(dns['value'])
            elif dns['type'] == 'A':
                a_records.append(dns['value'])

        whois = searchs_result['data']['attributes']['whois']

        last_analysis = searchs_result['data']['attributes']['last_analysis_results']
        data_analysis = {}
        #Save the Engine and the value into a dict.
        for engine in last_analysis:
            data_analysis[engine] = last_analysis[engine]['result']
 
        return render(
            request=request,
            template_name='domain_lookup.html',
            context={
            'whois' : whois,
            'txt_records' : txt_records,
            'a_records' : a_records,
            'data_analysis' : data_analysis,  
            }
        )
    else:
        return render(
        request=request,
        template_name='search_domain.html',
        )
    
@login_required
def search_ip(request):
    if request.method == "POST":
        data = (request.POST)
        ip_address = data['ip_to_search']
        if is_valid_ipv4_address(ip_address):
            searchs_result = ip_report(data['ip_to_search'])
            regional_register = searchs_result['data']['attributes']['regional_internet_registry']
            country = searchs_result['data']['attributes']['country']
            bkav_clasif = searchs_result['data']['attributes']['last_analysis_results']['Bkav']['result']
            cmc_clasif = searchs_result['data']['attributes']['last_analysis_results']['CMC Threat Intelligence']['result']
            snort_clasif = searchs_result['data']['attributes']['last_analysis_results']['Snort IP sample list']['result']
            fortinet_clasif = searchs_result['data']['attributes']['last_analysis_results']['Fortinet']['result']
            google_clasfic = searchs_result['data']['attributes']['last_analysis_results']['Google Safebrowsing']['result']
    #        cert_https = searchs_result['data']['attributes']['last_https_certificate']['subject']
    #        alter_names = searchs_result['data']['attributes']['last_https_certificate']['extensions']['subject_alternative_name']
            final_reputation = searchs_result['data']['attributes']['reputation']
        else:
            return render(
        request=request,
        template_name='search_ip.html'
        )


 
        return render(
            request=request,
            template_name='ip_result.html',
            context={
            'regional_register' : regional_register,
            'country' : country,
            'bkav_clasif' : bkav_clasif,
            'cmc_clasif' : cmc_clasif,
            'snort_clasif' : snort_clasif,
            'fortinet_clasif' : fortinet_clasif,
            'google_clasfic' : google_clasfic,
            'final_reputation' : final_reputation,            
            }
        )
    else:
        return render(
        request=request,
        template_name='search_ip.html'
        )
    
@login_required
def home(request):
    return render(
        request=request,
        template_name='index.html',
    )

@login_required
def export_to_csv(request):
    incidents = IncidentManagement.objects.all()
    response = HttpResponse(content_type='text/csv')
    response['Content-Dispostion'] = 'attachment; filename=incidents_export.csv'
    writer = csv.writer(response)
    writer.writerow(['incident_number','review_operator','incident_state','registration_date','incident_comment'])
    incidents_fields = incidents.values_list('incident_number','review_operator','incident_state','registration_date','incident_comment')
    for incident in incidents_fields:
        writer.writerow(incident)
    return response

@login_required
def export_csv_condition(request,condition):
    '''Condition define period to export. 1 For actual month, 2 for last month, 3 for last 3 month'''
    if condition == 1:
        current_date = timezone.make_aware(datetime.datetime.now())
        start_date = current_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end_date = start_date.replace(month=start_date.month + 1) - datetime.timedelta(days=1)

        incidents = IncidentManagement.objects.filter(registration_date__gte=start_date,registration_date__lte=end_date)
        response = HttpResponse(content_type='text/csv')
        response['Content-Dispostion'] = 'attachment; filename=incidents_export.csv'
        writer = csv.writer(response)
        writer.writerow(['incident_number','review_operator','incident_state','registration_date','incident_comment'])
        incidents_fields = incidents.values_list('incident_number','review_operator','incident_state','registration_date','incident_comment')
        for incident in incidents_fields:
            writer.writerow(incident)
        return response
    
    elif condition == 2:
        current_date = timezone.make_aware(datetime.datetime.now())
        start_date, end_date = get_last_month_dates(current_date)
        incidents = IncidentManagement.objects.filter(registration_date__gte=start_date,registration_date__lte=end_date)
        response = HttpResponse(content_type='text/csv')
        response['Content-Dispostion'] = 'attachment; filename=incidents_export.csv'
        writer = csv.writer(response)
        writer.writerow(['incident_number','review_operator','incident_state','registration_date','incident_comment'])
        incidents_fields = incidents.values_list('incident_number','review_operator','incident_state','registration_date','incident_comment')
        for incident in incidents_fields:
            writer.writerow(incident)
        return response
    
    else:
        return HttpResponse('Error, Invalid Argument')



class IncidentCreateView(LoginRequiredMixin,CreateView):
    model = IncidentManagement
    form_class = IncidentMgmtForm
    success_url = reverse_lazy('show_incident')
    template_name = 'create_incident.html'

    def form_valid(self, form):
        cleaned_data = form.cleaned_data
        incident_state = str(cleaned_data['incident_state'])
        email_message = (f'Nuevo Caso\nEstado: {incident_state}')
        title = f'Registro de Case'
        form.instance.case_creator = self.request.user
        send_email(title=title, message=email_message,)
        return super().form_valid(form)
        

class IncidentListView(LoginRequiredMixin,ListView):
    
    model = IncidentManagement
    template_name = 'list_incident.html'

    def get_context_data(self, **kwargs):
        '''defining the get_context_data to get more data'''
        context = super().get_context_data(**kwargs)
        context['extra_data'] = self.get_graph()
        return context

    def get_graph(self):
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
        # Save the chart to a PNG image and return it as an HTTP response
        context = {
            'chart_path': chart_path,
        }
        return context
    

class IncidentDetailView(LoginRequiredMixin,DetailView):
    login_url = '/login/'
    redirect_field_name = 'show_incident'
    model = IncidentManagement
    success_url = reverse_lazy('show_incident')
    template_name = "detail_incident.html"

    def get_context_data(self, **kwargs):
        '''defining the get_context_data to get more data'''
        context = super().get_context_data(**kwargs)
        incident_id = self.kwargs.get('pk')
        context['extra_data'] = self.time_to_response(incident_id)
        context['comments'] = self.publication_list(incident_id)
        return context
    
    def time_to_response(self, incident_id):

        case_date = IncidentManagement.objects.filter(pk=incident_id).values('registration_date').first()['registration_date']
        date_now = timezone.make_aware(datetime.datetime.now())
        context = date_now - case_date
        return context
    
    def publication_list(self, incident_id):

        comments = CaseComment.objects.filter(case_key = incident_id)

        return comments


class IncidentUpdateView(LoginRequiredMixin,UpdateView):
    model = IncidentManagement
    fields = ['review_operator','incident_state']
    success_url = reverse_lazy('show_incident')
    template_name = "edit_incident.html"

class IncidentCommentView(LoginRequiredMixin,CreateView):
    model = CaseComment
    fields = ['body']
    template_name = "comment_incident.html"

    def form_valid(self, form):
        form.instance.case_key = IncidentManagement.objects.get(pk=self.kwargs['pk'])
        form.instance.author = self.request.user
        return super().form_valid(form)
    
    def get_success_url(self):
        return reverse('incident_details', kwargs={'pk': self.kwargs['pk']})
    
    
@login_required
def case_chart(request):
    '''Funtion to graph bars charts'''
    open_cases = IncidentManagement.objects.filter(incident_state='Open').count()
    progress_cases = IncidentManagement.objects.filter(incident_state='Progress').count()

    fig = plt.figure(figsize=(8, 6))
    ax = fig.add_subplot(111)

    ax.bar(['Open', 'Progress'], [open_cases, progress_cases])

    ax.set_title('Cases Overview')
    ax.set_xlabel('Status')
    ax.set_ylabel('Number of Cases')
    chart_path = 'chart.png'
    fig.savefig('static/' + chart_path, format='png')
    # Save the chart to a PNG image and return it as an HTTP response
    context = {
        'chart_path': chart_path,
    }
    return render(request, 'bars.html', context)

@login_required
def graph_charts_js(request):
    open_cases = IncidentManagement.objects.filter(incident_state='Open').count()
    open_cases = int(open_cases)
    progress_cases = IncidentManagement.objects.filter(incident_state='Progress').count()
    progress_cases = int(progress_cases)

    case_status = ['Open','Progress']
    case_data = [open_cases,progress_cases]

    context = {
        'case_status' : case_status,
        'case_data' : case_data,
    }
    return render(request, 'chartsjs.html', context )
    pass

    

class IncidentOwnView(LoginRequiredMixin, ListView):
    model = IncidentManagement
    template_name = 'list_own_incidents.html'
    context_object_name = 'cases'

    def get_queryset(self):
        return IncidentManagement.objects.filter(review_operator=self.request.user)
    
@login_required    
def ip_scanner_tool(request):
    if request.method == "POST":
        form = NumberForm(request.POST)
        if form.is_valid():
            first_number = form.cleaned_data['num1']
            second_number = form.cleaned_data['num2']
            third_number = form.cleaned_data['num3']
            scan_network(first_number,second_number, third_number)
            return redirect(dashboard)
            
    else:
        form = NumberForm()
        return render(request, 'scan_network.html', {'form': form})

@login_required
def file_to_examinate(request):
    if request.method == 'POST':
        file = request.FILES.get('file')
        if file:
            file_id = upload_file(file)
            return render(request, 'file_upload_success.html', {'file_id': file_id})
        else:
            error_message = 'error', 'An error occurred.'
            return render(request, 'file_upload_failure.html', {'error_message': error_message})

    else:
        return render(request, 'upload_file.html')
    
import requests
from django.shortcuts import render

@login_required
def get_file_report(request, file_id):

    data = consult_file_report(file_id)
    if data:
        # Perform further operations with the file report data
        return render(request, 'file_report.html', {'report_data': data})
    else:
        # Error occurred during file report retrieval
        error_message = 'error', 'An error occurred.'
        return render(request, 'file_report_failure.html', {'error_message': error_message})
    

def show_scan_ids(request):
    file_with_ids = os.path.join(os.getcwd(), 'panel_app', 'static', 'file_scan_ids.txt')
    with open(file_with_ids, 'r') as f:
       for line in f:
            id_list = []
            id_list.append(line)
            
    return render (request, 'ids_list.html', {'ids_list': id_list})

class AboutView(TemplateView):
    template_name = 'about.html'


class CasesApiView(ListView):
    '''Return the lastest incident created in a HEAD request to the url'''
    model = IncidentManagement

    def head(self, *args, **kwargs):
        last_incident = self.get_queryset().latest('registration_date')
        response = HttpResponse(
            # RFC 1123 date format.
            headers={
                "all incidents": last_incident.registration_date.strftime(
                    "%a, %d %b %Y %H:%M:%S GMT"
                )
            },
        )
        return response
    
class AsynView(View):

    async def get(self, request, *args, **kwargs):
    # Perform io-blocking view logic using await, sleep for example.
        await asyncio.sleep(1)
        return HttpResponse("Hello async world!")
    
def current_currency(request):
    currency_list = get_current_currency()
    return render(request, 'currency_states.html', {'currency_list': currency_list})
