file1 = open("file2.txt", "r")
file2 = open("file1.txt", "r")
list1 = file1.readlines()
list2 = file2.readlines()
print "Unique in file2"
for i in list2:
	if i not in list1:
		print i

print "Unique in file1"
for i in list1:
	if i not in list2:
		print i
