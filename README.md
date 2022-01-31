## domain_report
### domain intelligence report generator (currently a command-line utility)  

**how to use:**  
- clone this git repository to your local machine  
- cd to the downloaded domain_report directory  
- pip install -r requirements.txt  
- python intel.py  
- follow the instructions for inputting domain, picking intelligence report generation options, and adding in censys credentials if appropriate    
      
**choices made:**  
- used the censys API to gather information about related IPs and subdomains to the user-inputted domain.   
- usd the RDAP API to gather informaiton about the registrar and registrant  
- provided MITRE ATT&CK TTP-based enrichment for the domain string  
- made these functionalities accessible from the management app intel.py, presented as a command-line utility    
- allowed user to input their censys API ID and secret through the command-line utility (once this is translated to its own REST API this will translate to providing this information in the body of the request to this API)  
- asked user for the type of censys API account they have (severe limitations on the API quota limit, so need to take this into account when doing anything with the API)  
  
**trade-offs:**  
- have had to be pretty minimal with my usage of censys API, as the free API key limitations (i.e. 120 p. 5 minute interval, with low overall call ceiling), so made use of RDAP API to gain some of the information I would otherwise have had to use the censys API for.   
- ideally this should be called as its own REST API to return the JSON through HTTP, however this was infeasible given the limited project time. this is unfortunate as using this in an automated capacity may prove challenging given we use input() to harvest required fields from the user.  
- would have been good to use Go to unlock concurrency for some of these scripts, for example we could facilitate all of ttpenrichment.py simultaneously if we had some Goroutines on the go. however given the time constraints mentioned, I opted for sticking with what I knew best.  
- unable to add significant fault tolerance to the censys API requests, this was just due to time constraints.  
  
**future improvements:**  
- have rate-limiting addressed through staggering HTTP requests as best as possible for censys API when using free API key.  
- add builtwith API functionality, so we can get a better understanding of services/software running on domain/subdomains.  
- provide all of this as a standalone REST API, so that the JSON provided can be used more effectively, and opening up this functionality to automation.  
- provide documentation for the outputted JSON so that it can be parsed and utilised more effectively by an end-user.  
- added further testing and fault tolerance around the censys API, and this would come part-and-parcel with the throttling-mitigation I'd like to add also.  
