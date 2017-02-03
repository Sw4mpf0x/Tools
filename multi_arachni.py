#!/usr/bin/env python
#
# Written by Andrew Luke (@sw4mp_f0x) and Steve Borosh (@424f424f)
#
#

from Queue import Queue
from threading import Thread
import subprocess
from optparse import OptionParser
import os
import datetime
from time import sleep

def worker(workerid):
    while not q.empty():
        try:
            # Pull target from Queue
            target = q.get()
            if target.split('//')[0].lower() == 'https:':
                target_file = target.split('/')[2] + '[s]'
            else:
                target_file = target.split('/')[2]
        except:
            break


        print('\x1b[1;31;40m' + workerid + ": scanning {}...".format(target) + '\x1b[0m')
        
        # Run Arachni against target
        cmd1 = './arachni {} --timeout {} --report-save-path=/opt/arachni-1.4-0.5.10/bin/output/{}/{}.afr'.format(target,timeout,projectname,target_file)
        
        # Generate HTML and TXT reports from results
        cmd2 = './arachni_reporter output/{}/{}.afr --reporter=txt:outfile=complete/{}/{}.txt'.format(projectname,target_file,projectname,target_file)
        cmd3 = './arachni_reporter output/{}/{}.afr --reporter=html:outfile=complete/{}/{}.html.zip'.format(projectname,target_file,projectname,target_file)
        try:
            task = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE)
            # Prints output and waits until subprocess is complete before continuing
            out = task.communicate()[0]
            print out

            print('\x1b[1;31;40m' + workerid + ': Building reports for ' + target_file + '\x1b[0m')
            print subprocess.Popen(cmd2, shell=True, stdout=subprocess.PIPE).stdout.read()
            print subprocess.Popen(cmd3, shell=True, stdout=subprocess.PIPE).stdout.read()
            q.task_done()
        except Exception as e:
            print e
        print('\x1b[1;31;40m' + workerid + ': ' + target_file + ' Complete!' + '\x1b[0m')
    print('\x1b[1;31;40m' + workerid + ': No more targets. Exiting.' + '\x1b[0m')      


def main():
    
    # Argument parsing
    usage = "usage: %prog -p ProjectName -f PathToFile [-t Timeout]"
    parser = OptionParser(usage=usage)
    parser.add_option('-p', '--project', action="store", help='Name used to identify the project', dest='projectname')
    parser.add_option('-f', '--file', action="store", help='File with list of URLs', dest='filename')
    parser.add_option('-t', '--timeout', action="store", help="Scan Timeout HOURS:MINUTES:SECONDS", dest='timeout', default='01:00:00')
    (options, args) = parser.parse_args()
    
    # Checking for required arguments
    if not options.projectname or not options.filename:
        parser.error("The project name and file name must be defined.")

    # Setting script variables
    file = options.filename
    global timeout
    timeout = options.timeout
    global projectname
    projectname = options.projectname
    global q
    q = Queue()
    num_worker_threads = 4
    totaltargets = 0
    current_worker = 0
    starttime = datetime.datetime.now()

    # Create project folders
    if not os.path.exists('/opt/arachni-1.4-0.5.10/bin/output/' + projectname):
        os.makedirs('/opt/arachni-1.4-0.5.10/bin/output/' + projectname)
    if not os.path.exists('/opt/arachni-1.4-0.5.10/bin/complete/' + projectname):
        os.makedirs('/opt/arachni-1.4-0.5.10/bin/complete/' + projectname)

    # Parse provided target file into Queue
    print('\x1b[1;31;40m' + 'Building Target Queue...' + '\x1b[0m')
    with open(file) as f:
        for url in f:
            try:
                target = url.strip()
                q.put(target)
                totaltargets += 1
                print 'URL Added.'
            except Exception as e:
                print e
        f.close()

    # Create and label workers
    print('\x1b[1;31;40m' + 'Creating Workers...' + '\x1b[0m')
    for i in range(num_worker_threads):
        current_worker += 1
        workerid = 'Worker-' + str(current_worker)
        t = Thread(target=worker,name=workerid, args=(workerid,))
        t.daemon = True
        t.start()
        print workerid + ' Created.'

    # Until the Queue is empty, print a status update every 3 minutes
    sleep(10)
    while not q.empty():
        currenttargets = q.qsize()
        currenttime = datetime.datetime.now()
        elapsedtime = currenttime - starttime
        print('\x1b[1;31;40m' + '=============Scan Status=============' + '\x1b[0m')
        print('\x1b[1;31;40m' + 'Total targets: ' + str(totaltargets) + '\x1b[0m')
        print('\x1b[1;31;40m' + 'Remaining targets: ' + str(currenttargets) + '\x1b[0m')
        print('\x1b[1;31;40m' + 'Time: ' + str(elapsedtime) + '\x1b[0m')
        sleep(180)

    q.join()
    endtime = datetime.datetime.now()
    totaltime = endtime - starttime
    
    # Merge afr files and generate merged report
    print('\x1b[1;31;40m' + 'Building final, merged report...' + '\x1b[0m')
    cmd1 = './arachni_script merge.rb output/{}/* output/{}/MERGED.afr'.format(projectname,projectname)
    cmd2 = './arachni_reporter output/{}/MERGED.afr --reporter=html:outfile=complete/{}/MERGED_REPORT.html.zip'.format(projectname,projectname)
    task1 = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE)
    out = task1.communicate()[0]
    print out

    task2 = subprocess.Popen(cmd2, shell=True, stdout=subprocess.PIPE)
    out = task2.communicate()[0]
    print out

    # Completion notice
    print('\x1b[1;31;40m' + 'Report Complete.' + '\x1b[0m')
    print('\x1b[1;31;40m' + '=============Scans Complete=============' + '\x1b[0m')
    print('\x1b[1;31;40m' + 'Total targets: ' + str(totaltargets) + '\x1b[0m')
    print('\x1b[1;31;40m' + 'Time: ' + str(totaltime) + '\x1b[0m')

if __name__ == "__main__":
    main()




