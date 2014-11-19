Todo
====

## Statistical Output

* Identify which information should be reported about real time traffic
* Ensure the necessary information is being captured
* Create (console or GUI?) output that conveys this information
    * What would be really nice is GUI output with the distributions graphed with some graphing library - updated in semi-real time

## Anomaly Detection

* Identify which distributions should be captured
    * ~~Currently capturing packet length distribution and destination port distribution~~
* ~~Ensure the necessary information is being captured~~
* Calculate entropy for a given distribution
* Ability to compare the entropy of two distributions to find anomalous usage
* Create baseline distributions
    * Should this be in a given time or over a given number of packets?
* Add capture of windowed traffic
* Compare windowed distributions to baseline distributions and output warning (to output GUI preferably)

## Paper

* All of it
