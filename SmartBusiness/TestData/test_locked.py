import csv

locked_user_path = 'C:\Repo_GitHub\PAICenter\PaiControl\TestData\locked_accounts.csv'
with open(locked_user_path, newline='') as csvfile:
    locked_users = csv.reader(csvfile, quotechar='|')
    next(locked_users)
    total_row = len(locked_users)
    for row in locked_users:
        print(row[1])
    