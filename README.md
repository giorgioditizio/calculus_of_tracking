# A Calculus of Tracking: Theory and Practice
This repository contains scripts and a fragment of a database to complement the paper "A Calculus of Tracking: Theory and Practice", to appear in PETS 2021 ([author's preprint](https://giorgioditizio.github.io/papers/calculus_pets2021.pdf)). The scripts enable the extraction of ground data from the database and the instantiation of the model to evaluate efficiency of different privacy mitigations (AdBlock Plus, Disconnect, etc.) as well as to formally prove tracking practices and COPPA compliance requirements. Below you find examples data with detailed instructions as well as steps to reproduce the key figures in our paper.

## Scripts quick description
The core of the repository relies in the 'Scripts_and_Data' folder. The key scripts are:
- `formal_model_extraction_sqlite.py` : the script interacts with the DB and create different .CSV files containing the different instantiate predicates of the model.
- `DBCrawlerSqlite.py` : the script contains a set of queries utilized by `formal_model_extraction_sqlite.py` to extract data from the DB.
- `proof_problem_generator.py` and `proof_problem_COPPA.py` : starting from the CSV files generated by `formal_model_extraction_sqlite.py`, generate the TPTP input problem for the prover.


## Setup

To setup, clone this repository, create a [Python virtual environment](https://docs.python.org/3/library/venv.html) and run the following command to install the package required.
```sh
pip install -r requirements.txt.
```

To obtain the proof we employed General Architecture for Proof Theory (GAPT). You can download the lastest release and the user manual [here](https://www.logic.at/gapt/). Later we provide the sequence of commands required to generate a proof from the output of the scripts using GAPT.
GAPT requires Java to correctly run (tested with OpenJDK 11.0.9.1). You can install it as follow (for Linux):
```sh
sudo apt install default-jre
```

## Instantiation of Predicates

We provide a sample of a OpenWPM database [here](https://drive.google.com/file/d/1OPFiTVrwzpRLBt7iSVJ_bshOEBEl1cwI/view?usp=sharing) (Top 100 Alexa domains only ~ 1.6GB size) obtained from WebCensus to instantiate the model. Download the database and place it in the 'Scripts_and_Data' folder. It is possible to generate a sequence of CSV files that contain the instantiation of the model's predicates using the `formal_model_extraction_sqlite.py` script.

The command to execute is:
```sh
$ python formal_model_extraction_sqlite.py MITIGATION_NAME NUMBER_WEBSITES [new|old]
```
where:
- `MITIGATION_NAME`: identify the mitigation to apply for the instantiation of the predicates. Options available are: disconnect, ghostery, adblock, elep, and privacybadger for the Disconnect, Ghostery, AdBlock Plus, AdBlock Plus w/ EasyList & EasyPrivacy, and Privacy Badger mitigations respectively.
- `NUMBER_WEBSITES`: identify the number of websites to consider as visited from the DB Top Alexa domains. We suggest to start playing with few domains.
- `[new|old]`: identify the source of data for the mitigation. Use new to employ the blacklist from 2019. Use old to employ the blacklist from 2016 from the Bashir et al. [paper](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/bashir) "Tracing Information Flows Between Ad Exchanges Using Retargeted Ads" in Proc. of USENIX-16.

An example
```sh
$ python formal_model_extraction_sqlite.py disconnect 30 new
```

### Output
The script produces a sequence of CSV files:
- dom_blocked.txt: contains the list of domains blocked by the mitigation during the visit of the domains.
- edge_tracking_flow.csv: contains the list of *Inclusion* and *Redirection* predicates.
- edge_link.csv: contains the list of *Link* predicates.
- edge_access.csv: contains the list of *Access* predicates.
- edges_cookie_sync.csv: contains the list of *Access* predicates enriched with the *Cookie Syncing* predicates from the Bashir et al. [paper](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/bashir).
- edge_knows.csv: contains the list of *Knows* predicates w/o considering the ones generated via cookies syncing.
- edge_final.csv: contains the final list of *Knows* predicates by also considering the generation through cookie syncing.

The folder *Example_50* contains examples of the outputs for different mitigations for the Top 50 Alexa domains. 

## TPTP Problem generation
**After** running the `formal_model_extraction_sqlite.py`, it is possible to generate a TPTP problem to determine a proof for a *Knows* or a *req_COPPA* predicate for Slakje by running the following script:

```sh
$ python proof_problem_generator.py DOMAIN_TRACKER DOMAIN_TRACKED
```
where:
- `DOMAIN_TRACKER`: is the domain that will be able to track users on the `DOMAIN_TRACKED`
- `DOMAIN_TRACKED`: is the domain visited by the user for which a `DOMAIN_TRACKER` knows of the visit.

or 

```sh
$ python proof_problem_COPPA.py DOMAIN_REQUIRE_COPPA
```
where:
- `DOMAIN_REQUIRE_COPPA`: is the domain for which we want to determine if it should comply with COPPA

Both scripts requires the following files to be available in the same folder: *'cookie_matching_partners_bahsir.txt'*, *'edges_tracking_flow.csv'*, and *'dom_blocked.txt'*. The last two files are obtained as output from `formal_model_extraction2019.py`. The `proof_problem_COPPA.py` also requires the file *'kids_top50.txt'* that is the list of Top 50 websites for kids by Alexa.

An example
```sh
$ python proof_problem_generator.py fbcdn.net facebook.com
```

or 

```sh
$ python proof_problem_COPPA.py flashtalking.com
```

### Output
The script produces a set of intermediate files (*'problem_tmp.p'* and *'problem_no_dupl.p'*) and a final file that contains the input for the prover: *'problem_input.p'*.

## Proof generation with GAPT

Our script automatically generate a problem in the [TPTP language](http://www.tptp.org/TPTP/SyntaxBNF.html). Place the problem file *'problem_input.p'*, the *'axioms.ax'* and *'axioms_coppa.ax'* files (that contain the rules of the model) in the folder '$GAPT_FOLDER/examples/tptp/'. Given an instance of GAPT in your system you can upload and run Slakje over the problem as follow. In the folder that contains the GAPT script run the following commands:
```sh
$ ./gapt.sh
gapt> val problem = TptpImporter.loadWithIncludes("examples/tptp/problem_input.p")
gapt> val final_problem = problem.toSequent
gapt> val proof = Slakje.getLKProof(final_problem)
gapt> prooftool(proof)
```
For more information about GAPT and Slakje refer to the official [user manual](https://www.logic.at/gapt/downloads/gapt-user-manual.pdf). 

If a proof exist, the output will shows the sequence of rules to execute to obtain the desired output.

### Timing for Proof Generation
The time required for the generation of a successful proof ranges from few seconds (`NUMBER_WEBSITES`~ 5-50) to several minutes (`NUMBER_WEBSITES`~ 100). Please refer to Section 5 and Tab.6 in the paper for further details.

### Example of expected GAPT's output

We provide an example of the correct execution of GAPT with its output:
```sh
gapt> val problem = TptpImporter.loadWithIncludes("examples/tptp/problem_input.p")
problem: gapt.formats.tptp.TptpFile =
fof(var1, axiom, includeContent('google.com', 'google.com')).
fof(var2, axiom, redirect('google.com', 'google.com')).
fof(var3, axiom, redirect('google.com', '')).
fof(var4, axiom, includeContent('google.com', 'gstatic.com')).
fof(var5, axiom, includeContent('youtube.com', 'youtube.com')).
fof(var6, axiom, redirect('youtube.com', 'youtube.com')).
fof(var7, axiom, redirect('youtube.com', '')).
fof(var8, axiom, includeContent('youtube.com', 'ggpht.com')).
fof(var9, axiom, includeContent('youtube.com', 'ytimg.com')).
fof(var10, axiom, includeContent('youtube.com', 'gstatic.com')).
fof(var11, axiom, includeContent('youtube.com', 'doubleclick.net')).
fof(var12, axiom, includeContent('youtube.com', 'google.com')).
fof(var13, axio...
```

```sh
gapt> val final_problem = problem.toSequent
final_problem: gapt.proofs.HOLSequent =
includeContent('google.com', 'google.com'),
redirect('google.com', 'google.com'),
redirect('google.com', ''),
includeContent('google.com', 'gstatic.com'),
includeContent(\#c('youtube.com': i), \#c('youtube.com': i)),
redirect(#c('youtube.com': i), #c('youtube.com': i)),
redirect(#c('youtube.com': i), ''),
includeContent(#c('youtube.com': i), 'ggpht.com'),
includeContent(#c('youtube.com': i), #c('ytimg.com': i)),
includeContent(#c('youtube.com': i), 'gstatic.com'),
includeContent(#c('youtube.com': i), 'doubleclick.net'),
includeContent(#c('youtube.com': i), 'google.com'),
includeContent('facebook.com', 'facebook.com'),
redirect('facebook.com', 'facebook.com'),
redirect('facebook.com', ''),
includeContent('facebook.com', 'fbc...
```

```sh
gapt> val proof = Slakje.getLKProof(final_problem)
proof: Option[gapt.proofs.lk.LKProof] =
Some([p19] ∀W
  ∀W1
  (#c(visit: i>o)(W) ∧ access(W, W1) ∧ ¬block_tp_cookie(W1) → knows(W1, W)),
#c(visit: i>o)('qq.com'),
∀W ∀W1 (link(W, W1) ∧ ¬block_requests(W1) → access(W, W1)),
∀W ∀W1 (includeContent(W, W1) → link(W, W1)),
includeContent('qq.com', 'revsci.net'),
¬block_requests('revsci.net'),
¬block_tp_cookie('revsci.net')
⊢
knows('revsci.net', 'qq.com')    (ForallLeftRule(p18, Ant(0), ∀W1 (#c(visit: i>o)(W) ∧ access(W, W1) ∧ ¬block_tp_cookie(W1) → knows(W1, W)), 'qq.com', W))
[p18] ∀W1
  (#c(visit: i>o)('qq.com') ∧ access('qq.com', W1) ∧ ¬block_tp_cookie(W1) →
    knows(W1, 'qq.com')),
#c(visit: i>o)('qq.com'),
∀W ∀W1 (link(W, W1) ∧ ¬block_requests(W1) → access(W, W1)),
∀W ∀W1 (includeContent(W, W1) → link(W, W1)),...
```

## Efficacy of mitigations
The MATLAB script `Plot_efficacy.m` plots the performance of different mitigations in terms of *Knows* and *Access* predicates obtained from the instantiation of the model.

The MATLAB script reads a sequence of CSV files in the folder *CSV*:
- *Access_graph_2016.csv*: contains the number of distinct *Access* predicates obtained from the instantiation with a certain mitigation for different Top Alexa domains visited in the 2016 DB. The mitigations are: '',G,D,A for no mitigation, Ghostery, Disconnect, and AdBlock Plus respectively.
- *Access_graph_2019.csv*: contains the number of distinct *Access* predicates obtained from the instantiation with a certain mitigation for different Top Alexa domains visited in the 2019 DB. The mitigations are: '',D,A,ELEP,PB for no mitigation, Disconnect, AdBlock Plus, AdBlock Plus enforced w/ *EasyList&EasyPrivacy*, and Privacy Badger respectively.
- *Knows_graph_2016.csv*: contains the number of distinct *Knows* predicates obtained from the instantiation with a certain mitigation for different Top Alexa domains visited in the 2016 DB. The mitigations considered are the same as in the *Access_graph_2016.csv* file.
- *Knows_graph_2019.csv*: contains the number of distinct *Knows* predicates obtained from the instantiation with a certain mitigation for different Top Alexa domains visited in the 2019 DB. The mitigations considered are the same as in the *Access_graph_2019.csv* file. 

This data are extracted from the output files of the `formal_model_extraction_sqlite.py` script.
## License
[MIT License](LICENSE)
