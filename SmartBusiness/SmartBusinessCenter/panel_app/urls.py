from django.urls import path
from panel_app.views import  (
    dashboard,
    search_domain,
    search_ip,
    IncidentCreateView,
    IncidentListView,
    IncidentDetailView,
    IncidentUpdateView,
    export_to_csv,
    export_csv_condition,
    IncidentCommentView,
    IncidentOwnView,
    ip_scanner_tool,
    file_to_examinate,
    show_scan_ids,
    get_file_report,
    AboutView,
    CasesApiView,
    AsynView,
    current_currency    
                              )

urlpatterns = [
    
    path('home/', dashboard, name='home'),
    path('search-domain/', search_domain, name='search_domain'),
    path('search-ip/', search_ip, name='search_ip'),
    path('create-incident/', IncidentCreateView.as_view(), name='create_incident'),
    path('show-incident/', IncidentListView.as_view(), name='show_incident'),
    path('incident-details/<int:pk>/', IncidentDetailView.as_view(), name="incident_details"),
    path('update-incident/<int:pk>/', IncidentUpdateView.as_view(), name="update_incident"),
    path('export-to-csv/', export_to_csv, name='export_to_csv' ),
    path('export-csv/<int:condition>', export_csv_condition, name='export_csv'),
    path('comment-case/<int:pk>/', IncidentCommentView.as_view(), name="comment_incident"),
    path('show-incident/myself/', IncidentOwnView.as_view(), name='show_own_incident'),
    path('network_scanner/', ip_scanner_tool, name='network_scanner'),
    path('upload-file/', file_to_examinate, name='upload_file'),
    path('scan-ids/', show_scan_ids, name='scan_ids'),
    path('file-report/<str:file_id>/', get_file_report, name='get_file_report'),
    path('about/',AboutView.as_view(), name='about'),
    path('case-api/',CasesApiView.as_view(), name='case_api'),
    path('case-asyn/',AsynView.as_view,name='case_asyn'),
    path('currency/',current_currency,name='currency')
    

    
]