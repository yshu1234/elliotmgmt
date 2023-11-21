1.  Feed websites into a queue.  Include a "done" check in the queue where a message reappears if it's not declared done within 10 minutes if it being taken off the queue. Have this script pull from the queue and attempt to check certificate state.  Scale instances of the script in batch processing as needed.  This seperates failure of the service(failure to receieve certificate info or failure to parse payload).

2.  Within the queue: Monitor the number of wesbites, alert and log on number of failures(websites taken off the queue without a done message).  This allows us to see if there's a large number of failures or a website that consistently failes. Within the service: Alert on payload receipt, payload parsing, and use the "done" check in the queue as an alert on completion. 

3.  Queued Version: Add domains/events to the queue have the request handled in the service depending on what it is.  
Standard Version: Add domains to the list "hosts" at the top of the script and it will automatically pick them up.  Create a new script for certificate expiry that follow a similar format and resuses parsing code if necessary.

4.  Break requests down into deliverables with clear key performance indicators. Use version control to keep track of how each request is reflected in code.
