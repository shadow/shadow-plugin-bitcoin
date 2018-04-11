import os
import argparse
import lxml.etree as ET
from subprocess import check_output

def setup_multiple_node_xml(node_num):
    baseline_xml = "../resource/example.xml"
    new_xml = "../resource/example_multiple_generated.xml"

    parser = ET.XMLParser(remove_blank_text=True, strip_cdata=False)

    tree = ET.parse(baseline_xml, parser)

    shadow = tree.getroot()

    for node in shadow.findall('node'):
        shadow.remove(node)

    for i in range(node_num):
        node_id = "bcdnode%d" % (i)

        node = ET.SubElement(shadow, "node", id=node_id)            
        time = str(5 + i/100)
        if i % 2 == 0:
            ET.SubElement(node, "application", plugin="bitcoind", time=time, arguments="-datadir=./data/bcdnode%d -debug -printtoconsole -listen -connect=bcdnode%d -disablewallet=1 -server=0"%(i, i+1))
        else:
            ET.SubElement(node, "application", plugin="bitcoind", time=time, arguments="-datadir=./data/bcdnode%d -debug -printtoconsole -listen -connect=bcdnode%d -disablewallet=1 -server=0"%(i, i-1))

    tree.write(new_xml, pretty_print=True)
    
def run_shadow_bitcoin_multiple_node(node_num, worker_num):
    run_path = "plugins/bitcoin"
    if os.path.exists("./data"):
        i = raw_input("data directory (./data) already exist. Do you want to remove?([y]/n)")
        if i == "" or i == "y":
            os.system("rm -rf ./data")

    for i in range(node_num):
        os.system("mkdir -p ./data/bcdnode%d" % i)

    os.system("shadow -w %d %s" % (worker_num, "../resource/example_multiple_generated.xml"))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Script for generating shadow config xml and running shadow experiments.' )
    parser.add_argument("--nodenum", type=int, help="Number of bitcoin nodes for experiment.")
    parser.add_argument("--workernum", type=int, help="Number of shadow workers for the simulation. Multiple worker can accelerate the speed of the simulation.")

    args = parser.parse_args()
    if args.nodenum == None:
        print "Need --nodenum option. usage: run_multinode_experiment.py --nodenum 100"
        exit(1)
    if args.workernum == None:
        args.workernum = 1

    setup_multiple_node_xml(args.nodenum)
    run_shadow_bitcoin_multiple_node(args.nodenum, args.workernum)

    
