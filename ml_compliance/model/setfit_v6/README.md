---
tags:
- setfit
- sentence-transformers
- text-classification
- generated_from_setfit_trainer
widget:
- text: "Policy: Zone-based firewall policies must separate network segments\nRule:\
    \ CIS-4.1\nEvidence: ! FWSM-61 Configuration\n! Generated: 2024-01-11\n!\nhostname\
    \ FWSM-61\n\n### No zone-based firewall configured\ninterface GigabitEthernet0/0\n\
    \ ip address 192.168.1.1 255.255.255.0\n no shutdown\ninterface GigabitEthernet0/1\n\
    \ ip address 10.0.0.1 255.255.255.0\n no shutdown"
- text: "Policy: Default usernames such as admin or root should be changed\nRule:\
    \ CIS-1.1\nEvidence: # -*- restclient -*-\n\n# Settings\n:node = asr-101\n:addr\
    \ = 50.196.141.39\n:deviceusername = <username>\n:devicepassword = <password>\n\
    :host = http://localhost:8181\n:basic-auth := (format \"Basic %s\" (base64-encode-string\
    \ (format \"%s:%s\" \"admin\" \"admin\")))\n\n# Create ASR 101\nPOST :host/restconf/config/network-topology:network-topology/topology/topology-netconf/node/controller-config/yang-ext:mount/config:modules\n\
    Authorization: :basic-auth\nContent-Type: application/xml\n<module xmlns=\"urn:opendaylight:params:xml:ns:yang:controller:config\"\
    >\n   <type xmlns:prefix=\"urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf\"\
    >prefix:sal-netconf-connector</type>\n   <name>:node\n   </name>\n   <address\
    \ xmlns=\"urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf\"\
    >:addr\n   </address>\n   <port xmlns=\"urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf\"\
    >830</port>\n   <username xmlns=\"urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf\"\
    >:deviceusername</username>\n   <password xmlns=\"urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf\"\
    >:devicepassword</password>\n   <tcp-only xmlns=\"urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf\"\
    >false</tcp-only>\n   <event-executor xmlns=\"urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf\"\
    >\n     <type xmlns:prefix=\"urn:opendaylight:params:xml:ns:yang:controller:netty\"\
    >prefix:netty-event-executor</type>\n     <name>global-event-executor</name>\n\
    \   </event-executor>\n   <binding-registry xmlns=\"urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf\"\
    >\n     <type xmlns:prefix=\"urn:opendaylight:params:xml:ns:yang:controller:md:sal:binding\"\
    >prefix:binding-broker-osgi-registry</type>\n     <name>binding-osgi-broker</name>\n\
    \   </binding-registry>\n   <dom-registry xmlns=\"urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf\"\
    >\n     <type xmlns:prefix=\"urn:opendaylight:params:xml:ns:yang:controller:md:sal:dom\"\
    >prefix:dom-broker-osgi-registry</type>\n     <name>dom-broker</name>\n   </dom-registry>\n\
    \   <client-dispatcher xmlns=\"urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf\"\
    >\n     <type xmlns:prefix=\"urn:opendaylight:params:xml:ns:yang:controller:config:netconf\"\
    >prefix:netconf-client-dispatcher</type>\n     <name>global-netconf-dispatcher</name>\n\
    \   </client-dispatcher>\n   <processing-executor xmlns=\"urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf\"\
    >\n     <type xmlns:prefix=\"urn:opendaylight:params:xml:ns:yang:controller:threadpool\"\
    >prefix:threadpool</type>\n     <name>global-netconf-processing-executor</name>\n\
    \   </processing-executor>\n </module>\n\n# Get node operational status\nGET :host/restconf/operational/network-topology:network-topology/topology/topology-netconf/node/:node/\n\
    Authorization: :basic-auth\n\n# Get interface configuration\nGET :host/restconf/operational/network-topology:network-topology/topology/topology-netconf/node/:node/yang-ext:mount/Cisco-IOS-XR-ifmgr-cfg:interface-configurations/\n\
    Authorization: :basic-auth\nAccept: application/xml\n\n# Get operational l2vpn\
    \ xconnect groups\nGET :host/restconf/operational/network-topology:network-topology/topology/topology-netconf/node/:node/yang-ext:mount/Cisco-IOS-XR-l2vpn-cfg:l2vpn/database/xconnect-groups/xconnect-group/local\n\
    Authorization: :basic-auth\nAccept: application/xml\n\n# Show\nGET :host/restconf/config/network-topology:network-topology/topology/topology-netconf/node/controller-config/yang-ext:mount/config:modules/module/odl-sal-netconf-connector-cfg:sal-netconf-connector/:node\n\
    Authorization: :basic-auth\n\n# Delete\nDELETE :host/restconf/config/network-topology:network-topology/topology/topology-netconf/node/controller-config/yang-ext:mount/config:modules/module/odl-sal-netconf-connector-cfg:sal-netconf-connector/:node\n\
    Authorization: :basic-auth"
- text: 'Policy: Network devices must forward security events to approved centralized
    logging

    Rule: CIS-2.1

    Evidence: ! Generated: 2024-01-07

    !

    hostname RTR-19-16

    version 15.7

    logging host 223.145.92.214

    logging trap informational'
- text: "Policy: SNMP configuration must avoid well-known community names\nRule: CIS-3.1\n\
    Evidence: ! SW-10-63 Configuration\n!\nhostname SW-10-63\nsnmp-server community\
    \ security-audit RO\ninterface Vlan4\n ip address 176.214.192.228 255.255.255.0\n\
    \ no shutdown\n!"
- text: "Policy: SNMP must use secure community names and modern protocol versions\n\
    Rule: CIS-3.1\nEvidence: ! Generated: 2024-01-21\n!\nhostname RTR-13-88\nversion\
    \ 15.7\nsnmp-server community datacenter RO\ninterface GigabitEthernet1/1\n ip\
    \ address 72.25.205.76 255.255.255.0\n no shutdown\n!"
metrics:
- accuracy
pipeline_tag: text-classification
library_name: setfit
inference: true
base_model: sentence-transformers/all-MiniLM-L6-v2
---

# SetFit with sentence-transformers/all-MiniLM-L6-v2

This is a [SetFit](https://github.com/huggingface/setfit) model that can be used for Text Classification. This SetFit model uses [sentence-transformers/all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) as the Sentence Transformer embedding model. A [LogisticRegression](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html) instance is used for classification.

The model has been trained using an efficient few-shot learning technique that involves:

1. Fine-tuning a [Sentence Transformer](https://www.sbert.net) with contrastive learning.
2. Training a classification head with features from the fine-tuned Sentence Transformer.

## Model Details

### Model Description
- **Model Type:** SetFit
- **Sentence Transformer body:** [sentence-transformers/all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2)
- **Classification head:** a [LogisticRegression](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html) instance
- **Maximum Sequence Length:** 256 tokens
- **Number of Classes:** 2 classes
<!-- - **Training Dataset:** [Unknown](https://huggingface.co/datasets/unknown) -->
<!-- - **Language:** Unknown -->
<!-- - **License:** Unknown -->

### Model Sources

- **Repository:** [SetFit on GitHub](https://github.com/huggingface/setfit)
- **Paper:** [Efficient Few-Shot Learning Without Prompts](https://arxiv.org/abs/2209.11055)
- **Blogpost:** [SetFit: Efficient Few-Shot Learning Without Prompts](https://huggingface.co/blog/setfit)

### Model Labels
| Label | Examples                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|:------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1     | <ul><li>'Policy: Default usernames such as admin or root should be changed\nRule: CIS-1.1\nEvidence: ! Generated: 2024-01-04\n!\nhostname RTR-58-60\nversion 15.7\nusername noc_analyst privilege 15 secret 5 $1$4401$hash\ninterface GigabitEthernet1/0\n ip address 24.80.155.212 255.255.255.0\n no shutdown\n!\ninterface GigabitEthernet0/1\n ip address 214.167.75.24 255.255.255.0\n no shutdown\n!'</li><li>'Policy: Default usernames such as admin or root should be changed\nRule: CIS-1.1\nEvidence: ! Generated: 2024-01-03\n!\nhostname RTR-97-30\nversion 15.7\nusername ops_team privilege 15 secret 5 $1$1017$hash'</li><li>'Policy: Default usernames such as admin or root should be changed\nRule: CIS-1.1\nEvidence: ! RTR-54-47 Configuration\n!\nhostname RTR-54-47\nversion 15.7\nusername security_ops privilege 15 secret 5 $1$8717$hash\ninterface GigabitEthernet0/0\n ip address 4.134.110.11 255.255.255.0\n no shutdown\n!'</li></ul>                                                                                                                                                                    |
| 0     | <ul><li>'Policy: Default usernames such as admin or root should be changed\nRule: CIS-1.1\nEvidence: ! Generated: 2024-01-13\n!\nhostname RTR-30-71\nversion 15.7\nusername test privilege 15 secret 5 $1$7858$hash\ninterface GigabitEthernet0/3\n ip address 77.40.202.232 255.255.255.0\n no shutdown\n!\ninterface GigabitEthernet0/1\n ip address 31.229.88.243 255.255.255.0\n no shutdown\n!'</li><li>'Policy: Default usernames such as admin or root should be changed\nRule: CIS-1.1\nEvidence: ! Generated: 2024-01-15\n!\nhostname RTR-93-1\nversion 15.7\nusername operator privilege 15 secret 5 $1$7875$hash\ninterface GigabitEthernet1/3\n ip address 90.192.51.213 255.255.255.0\n no shutdown\n!\ninterface GigabitEthernet1/1\n ip address 42.231.37.205 255.255.255.0\n no shutdown\n!'</li><li>'Policy: Default usernames such as admin or root should be changed\nRule: CIS-1.1\nEvidence: ! RTR-75-98 Configuration\n!\nhostname RTR-75-98\nversion 15.7\nusername admin privilege 15 secret 5 $1$2730$hash\ninterface GigabitEthernet1/2\n ip address 225.210.135.99 255.255.255.0\n no shutdown\n!'</li></ul> |

## Uses

### Direct Use for Inference

First install the SetFit library:

```bash
pip install setfit
```

Then you can load this model and run inference.

```python
from setfit import SetFitModel

# Download from the 🤗 Hub
model = SetFitModel.from_pretrained("setfit_model_id")
# Run inference
preds = model("Policy: Network devices must forward security events to approved centralized logging
Rule: CIS-2.1
Evidence: ! Generated: 2024-01-07
!
hostname RTR-19-16
version 15.7
logging host 223.145.92.214
logging trap informational")
```

<!--
### Downstream Use

*List how someone could finetune this model on their own dataset.*
-->

<!--
### Out-of-Scope Use

*List how the model may foreseeably be misused and address what users ought not to do with the model.*
-->

<!--
## Bias, Risks and Limitations

*What are the known or foreseeable issues stemming from this model? You could also flag here known failure cases or weaknesses of the model.*
-->

<!--
### Recommendations

*What are recommendations with respect to the foreseeable issues? For example, filtering explicit content.*
-->

## Training Details

### Training Set Metrics
| Training set | Min | Median  | Max |
|:-------------|:----|:--------|:----|
| Word count   | 9   | 50.5817 | 202 |

| Label | Training Sample Count |
|:------|:----------------------|
| 0     | 463                   |
| 1     | 534                   |

### Training Hyperparameters
- batch_size: (16, 16)
- num_epochs: (2, 5)
- max_steps: 1000
- sampling_strategy: oversampling
- body_learning_rate: (2e-05, 2e-05)
- head_learning_rate: 0.01
- loss: CosineSimilarityLoss
- distance_metric: cosine_distance
- margin: 0.25
- end_to_end: False
- use_amp: False
- warmup_proportion: 0.1
- l2_weight: 0.01
- max_length: 512
- seed: 42
- eval_max_steps: -1
- load_best_model_at_end: False

### Training Results
| Epoch | Step | Training Loss | Validation Loss |
|:-----:|:----:|:-------------:|:---------------:|
| 0.001 | 1    | 0.3100        | -               |
| 0.05  | 50   | 0.2676        | -               |
| 0.1   | 100  | 0.2666        | -               |
| 0.15  | 150  | 0.2595        | -               |
| 0.2   | 200  | 0.2499        | -               |
| 0.25  | 250  | 0.2303        | -               |
| 0.3   | 300  | 0.1949        | -               |
| 0.35  | 350  | 0.0791        | -               |
| 0.4   | 400  | 0.0394        | -               |
| 0.45  | 450  | 0.0336        | -               |
| 0.5   | 500  | 0.0332        | -               |
| 0.55  | 550  | 0.0325        | -               |
| 0.6   | 600  | 0.0239        | -               |
| 0.65  | 650  | 0.0294        | -               |
| 0.7   | 700  | 0.0239        | -               |
| 0.75  | 750  | 0.0250        | -               |
| 0.8   | 800  | 0.0206        | -               |
| 0.85  | 850  | 0.0209        | -               |
| 0.9   | 900  | 0.0164        | -               |
| 0.95  | 950  | 0.0225        | -               |
| 1.0   | 1000 | 0.0138        | 0.0355          |

### Framework Versions
- Python: 3.13.9
- SetFit: 1.2.0
- Sentence Transformers: 6.0.1
- Transformers: 5.17.0
- PyTorch: 2.6.0+cu124
- Datasets: 5.0.1
- Tokenizers: 0.23.1

## Citation

### BibTeX
```bibtex
@article{https://doi.org/10.48550/arxiv.2209.11055,
    doi = {10.48550/ARXIV.2209.11055},
    url = {https://arxiv.org/abs/2209.11055},
    author = {Tunstall, Lewis and Reimers, Nils and Jo, Unso Eun Seo and Bates, Luke and Korat, Daniel and Wasserblat, Moshe and Pereg, Oren},
    keywords = {Computation and Language (cs.CL), FOS: Computer and information sciences, FOS: Computer and information sciences},
    title = {Efficient Few-Shot Learning Without Prompts},
    publisher = {arXiv},
    year = {2022},
    copyright = {Creative Commons Attribution 4.0 International}
}
```

<!--
## Glossary

*Clearly define terms in order to be accessible across audiences.*
-->

<!--
## Model Card Authors

*Lists the people who create the model card, providing recognition and accountability for the detailed work that goes into its construction.*
-->

<!--
## Model Card Contact

*Provides a way for people who have updates to the Model Card, suggestions, or questions, to contact the Model Card authors.*
-->