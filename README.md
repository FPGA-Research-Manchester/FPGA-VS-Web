# FPGA Virus Scanner Website
### The [FPGA Virus Scanner website](https://fpga.cs.manchester.ac.uk/vs/) is online right now.

The FPGA Virus Scanner web application is an online interface to the FPGA Virus Scanners written by the UoM FPGA group.

The web application is mainly driven by feeding a data store with jobs, which are picked up by the scan job runner, and then expose the reports as HTML.

The Virus Scanner:
 - Provides a simple web interface for accessing the application
 - Allows users to upload their own bitstreams for virus scanning
 - Certified bitstreams can be completely described, and their designs downloaded as JSON or FASM
 - Job processing system to manage many user jobs over a long time period
 - Manages the preperation, deployment and outputs of the various FPGA scanning tools
 - Uses a simple JSON based store for the uploaded bitstream data
 - Exposes an API to access the scanning results programmatically


## FPGA Website Architecture
The fpga web application is driven by the tools it invokes, the website will load jobs into the job running engine, which will update the website when the jobs are completed.

![bitman](/public/img/fpga-vs-web.png)

## FPGA Website Tools

#### Bitman
<img src='/public/img/bitman.png' width='300px' />
Bitman is used to unpack the FPGA configuration data from the uploaded bistreams, it can be used to unpack xilinx .bit programming files from 7Series, UltraScale and UltraScale+ FPGA series, including multi-SLR devices.

#### Carpetner LUT
<img src='/public/img/carpenterlut.png' width='300px' />
The virus scanner uses the Carpenter LUT library to map FPGA configuration data into a set of configured primitives, and then convert the primitives back into a completed FPGA implementation graph. 

#### FPGA Virus Scanner
<img src='/public/img/virusscanner.png' width='300px' />
The main virus scanning engine takes the implemented FPGA graphs and traverses them looking for suspicious and malicous constructions. These signatures are reported back to the service via machine readable reports to be exposed to the user on the website. 

## Sponsors
<img src='/public/img/ncsc_logo.png' width='200px' /> The UK National Cyber Security Centre through the project rFAS (grant agreement 4212204/RFA 1597)

<img src='/public/img/amd_xilinx_logo.png' width='200px' /> We thank AMD/Xilinx for their generous support
