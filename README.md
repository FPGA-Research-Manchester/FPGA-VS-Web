# FPGA Virus Scanner Website

The FPGA Virus Scanner web application is an online interface to the FPGA Virus Scanners written by the UoM FPGA group.

The Virus Scanner:
 - Provides a simple web interface for accessing the application
 - Allows users to upload their own bitstreams for virus scanning
 - Certified bitstreams can be completely described, and their designs downloaded as JSON or FASM
 - Job processing system to manage many user jobs over a long time period
 - Manages the preperation, deployment and outputs of the various FPGA scanning tools
 - Uses a simple JSON based store for the uploaded bitstream data
 - Exposes an API to access the scanning results programmatically
