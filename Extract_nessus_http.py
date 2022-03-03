import xml.etree.ElementTree as ET
import sys

def gen_urls(nessus_file):
    tree = ET.parse(nessus_file)
    root = tree.getroot()
    urls = []
    # Loop through Report Children
    for host in root[1]:
        ip = host.attrib["name"]
        # Check each plugin to find web service detection
        for plugin in host:
            if "pluginName" in plugin.attrib and "svc_name" in plugin.attrib:
                if plugin.attrib["pluginName"] == "Service Detection" and plugin.attrib["svc_name"] == "www":
                    protocol = "https" if "TLS" in plugin[10].text else "http"
                    url = f'{protocol}://{ip}:{plugin.attrib["port"]}'
                    if url not in urls:
                        urls.append(url)
            #Assume that port 80 is http and port 443 is https if nessus is unsure
            if "pluginName" in plugin.attrib and "port" in plugin.attrib:
                if plugin.attrib["pluginName"] == "Nessus SYN scanner" and plugin.attrib["port"] in ["80", "443"]:
                    protocol = "https" if plugin.attrib["port"] == "443" else "http"
                    url = f'{protocol}://{ip}:{plugin.attrib["port"]}'
                    if url not in urls:
                        urls.append(url)
            

    with open("nessus_urls.txt", "w") as f:
        for url in urls:
            f.write(url + "\n")
        print("Done! nessus_urls.txt created!")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <Nessus file>")
    else:
        gen_urls(sys.argv[1])


if __name__ == "__main__":
    main()