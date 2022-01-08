import csv
with open('ver_time.csv','r')as f:
  data = csv.reader(f)
  for row in data:
        print(row)
