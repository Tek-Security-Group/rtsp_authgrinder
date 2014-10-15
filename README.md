rtsp_authgrinder.py
=================

rtsp_authgrind.py - A quick and simple tool to brute force credentials on RTSP services and devices. This is a multi-threaded brute forcing tool for testing, assessment and audit purposes only.

Copyright (C) 2014 Luke Stephens and Tek Security Group, LLC - all rights reserved
	
	This program is free software: you can redistribute it and/or modify
  	it under the terms of the GNU General Public License as published by
  	the Free Software Foundation, either version 3 of the License, or
  	(at your option) any later version.

  	This program is distributed in the hope that it will be useful,
  	but WITHOUT ANY WARRANTY; without even the implied warranty of
  	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  	GNU General Public License for more details.

  	You should have received a copy of the GNU General Public License
  	along with this program.  If not, see <http://www.gnu.org/licenses/>.
	
RTSP Authentication Grinder is provided for testing purposes only and is not authorized for use to conduct malicious, illegal or other nefarious activities.
	
Standard usage is:
	
	python rtsp_authgrind [- l username | -L username list file] [-p password 
	| -P password list file] <target ip [:port]>
	
Right now I would say it is "fair" speed. I can get 100,000+ credential checks through it in 12-15 min. My opinion is the major limiting factor is the device, not the program, as the device I am testing on seems to saturate at about ~120 checks per second.
	
A few things to know:
	1. rtsp devices can be overwhelmed so these default settings could easily cause an
	error: "Resource temporarily unavailable". Note there may be a bug that skips the
	checks when this happens, I am tracking that down.
	
	2. Starving the threads can happen (they block) if the THREADBLOCKSIZE is small. So
	if you have 10 threads and a block size of 10, you could get some of those threads
	doing a large amount of blocking on getting new work items, versus actually doing
	checks. I like the larger block size like 30, 50, 100... But it will have to depend
	on the number you have.
	
	3. This ONLY does BASIC auth right now. I have hooks in to do DIGEST auth later (see
	to do list)

To Do:
  1. Add DIGEST Auth
  2. Fix the skips I think are happening when service congestion occurs
  3. Fix the reporting... I would like for it to display the current speed and such, but what I originally did was clunky
  4. Update to add THREADS and THREADBLOCK sizes to command line params (-t THREADS, -b THREADBLOCK?).
  5. General speed and efficiencies
  6. Self throttling?
  7. Better reporting (like a -o file option that tees)?
