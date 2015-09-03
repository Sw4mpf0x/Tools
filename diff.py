#Show matched lines between two different files
file1 = open("file1.txt", "r")
file2 = open("file2.txt", "r")
list1 = file1.readlines()
list2 = file2.readlines()
for i in list2:
    for j in list1:
        if  i==j:
            print(i)
