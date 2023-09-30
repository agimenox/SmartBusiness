import pandas as pd
from datetime import date
from panel_app.models import FwAssign
from django.db import transaction

'''Compara el dia de hoy con la fecha de inicio en el csv'''
data_frame = pd.read_csv("C:/Users/gimenoa/OneDrive - GRUPO COMAFI/Documentos/OperacionesApp/TestData/responsable_fw.csv")

'''
week = date.today()
week = week.strftime("%d/%m/%Y")
print(week)
print(data_frame[data_frame['Inicio'] == week])
'''

#data_frame.to_sql(FwAssign._meta.db_table, if_exists='replace', con=engine, index=False)


with transaction.atomic():
    for index, row in data_frame.iterrows():
        FwAssign.objects.create(
            column_1=row['assigned_to'],
            column_2=row['initial_date'],
            column_3=row['end_date']
        )


#print(data_frame)
'''
today = date.today()
d1 = today.strftime("%d/%m/%Y")
print(d1)
'''