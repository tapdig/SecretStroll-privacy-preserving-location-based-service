## Part3 README

To perform data collection, you need to run `data_generation.py` file. Make sure that the Server is started and you run this script under Client docker image. To run it for 100 queries for each cell ID:

`python3 data_generation --num-tries 100`

To train classifier based on these collected network traces and display performance of the model, you need to run:

`python3 fingerprinting.py`

Collected network traces were too large, so we did not include it in submission. However, you can download "tor_pcap.zip" archive and extract it under part3 folder. Total size is ~4.4 GB. Here is the OneDrive link (accessible via "epfl.ch" email.) for download: https://epflch-my.sharepoint.com/:u:/g/personal/tapdig_maharramli_epfl_ch/Ednyqoe_WK5NpAwogE2FzcEBY2X1W0bqGpwQe8Y7Fcr3Ow?e=ziyMCg
