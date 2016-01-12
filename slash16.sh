#If a consistent gateway IP is used, this will help sift through a /16 
#so that you aren't feeding your scanner a bunch of non existent /24s.inc=1
#Used '/root/slash16.sh |grep -B 1 "2 received"' to run and grep out valid subnets.

for a in $(seq 1 254)
do
        if [[ $inc -lt 6 ]] #Currently set to scan 5 systems at the same time. "Multiprocessing" if you will.
        then
                ping -c 2 x.x.$a.x &  #gatway IP on each subnet. Sequencing through the 3rd octet
                ((inc++))
        else
                wait
                inc=1
        fi
done
