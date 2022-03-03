Script that extracts the urls from a .nessus file.

This includes anything that Nessus service detection finds to be http(s), and for cases where nessus is unsure, port 80 is assumed to be http and port 443 is assumed to be https.