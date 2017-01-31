## Overview

The firewall.py is a script to help generate iptables firewall rules that would restrict access to the enabled protocols from given countries.

## Background

Allowing traccar to listen on multiple protocol ports on the internet pauses an unknown risk if an unknown flaw ever exists in the application or libraries in use.
Partial solution is to lock it down to countries where it’s expected to be accessed from.
The python script assists in locking down traccar protocols to given countries. 
This is particularly useful if you want to only allow access from your country and neighbouring countries. 
If a car is stolen and it crosses the border to neighbouring countries, you’re still able to track it.


## How to run the script

python firewall.py -h

## License

    Apache License, Version 2.0

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
