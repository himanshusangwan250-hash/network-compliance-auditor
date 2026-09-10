---
tags:
- setfit
- sentence-transformers
- text-classification
- generated_from_setfit_trainer
widget:
- text: "Secure SNMP community naming and versioning is required || ! Generated: 2024-01-27\n\
    !\nhostname RTR-48-66\nversion 15.7\nsnmp-server community private RO\ninterface\
    \ GigabitEthernet1/1\n ip address 84.133.201.31 255.255.255.0\n no shutdown\n\
    !\ninterface GigabitEthernet1/3\n ip address 8.228.207.53 255.255.255.0\n no shutdown\n\
    !"
- text: 'Unique administrative accounts must replace default credentials || ! RTR-94-6
    Configuration

    !

    hostname RTR-94-6

    version 15.7

    username test privilege 15 secret 5 $1$9534$hash'
- text: 'Default usernames such as admin or root should be changed || ! Generated:
    2024-01-18

    !

    hostname RTR-13-7

    version 15.7

    username guest privilege 15 secret 5 $1$3516$hash'
- text: "Network segmentation through defined security zones is required || ! ===========================================================================\n\
    ! R2 HSRP configuration  (router, c7200/IOSv)  -- STANDBY (lower priority)\n!\
    \ ComputingForGeeks CCNA 200-301 lab: hsrp\n! https://computingforgeeks.com/ccna-labs-hsrp-configuration-on-gns3-and-packet-tracer/\n\
    !\n! Group 1, HSRP version 2, same virtual IP 192.168.10.254.\n! R2 has priority\
    \ 100 (default) + preempt, so it takes over only when R1 fails.\n! ===========================================================================\n\
    enable\nconfigure terminal\nhostname R2\ninterface GigabitEthernet0/0\n ip address\
    \ 192.168.10.2 255.255.255.0\n standby version 2\n standby 1 ip 192.168.10.254\n\
    \ standby 1 priority 100\n standby 1 preempt\n no shutdown\n exit\nend\nwrite\
    \ memory"
- text: "Network devices must forward security events to approved centralized logging\
    \ || ! Generated: 2024-01-22\n!\nhostname RTR-19-31\nversion 15.7\nlogging host\
    \ 196.153.222.106\nlogging trap informational\ninterface GigabitEthernet0/3\n\
    \ ip address 69.146.82.66 255.255.255.0\n no shutdown\n!"
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
| Label | Examples                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0     | <ul><li>'Default usernames such as admin or root should be changed || ! RTR-85-51 Configuration\n!\nhostname RTR-85-51\nversion 15.7\nusername cisco privilege 15 secret 5 $1$5944$hash\ninterface GigabitEthernet1/3\n ip address 167.162.89.182 255.255.255.0\n no shutdown\n!'</li><li>'Default usernames such as admin or root should be changed || ! Generated: 2024-01-28\n!\nhostname RTR-90-88\nversion 15.7\nusername root privilege 15 secret 5 $1$3201$hash\ninterface GigabitEthernet1/2\n ip address 187.213.45.49 255.255.255.0\n no shutdown\n!\ninterface GigabitEthernet1/1\n ip address 234.208.248.195 255.255.255.0\n no shutdown\n!'</li><li>'Default usernames such as admin or root should be changed || ! ===========================================================================\n! SW1 base configuration  (Layer 2 switch, IOSvL2)\n! ComputingForGeeks CCNA 200-301 lab: base-device\n! https://computingforgeeks.com/cisco-device-base-configuration/\n!\n! Paste at the privileged-EXEC prompt. RSA key generation takes a few seconds.\n! The management IP lives on the Vlan1 SVI (a switch has no routed Gi0/0 by default).\n! ===========================================================================\nenable\nconfigure terminal\nhostname SW1\nenable secret Cisc0-Lab!\nservice password-encryption\nip domain-name lab.example.com\nusername admin privilege 15 secret Adm1n-Lab!\ncrypto key generate rsa modulus 2048\nip ssh version 2\ninterface GigabitEthernet0/0\n no shutdown\n exit\ninterface Vlan1\n ip address 192.168.10.2 255.255.255.0\n no shutdown\n exit\nline vty 0 4\n login local\n transport input ssh\n exit\nbanner motd #Authorized access only. Activity is logged.#\nend\nwrite memory\n\nusername test privilege 15 secret 5 $1$1987$hash\ninterface GigabitEthernet0/3\n description WAN Interface\n ip address 74.209.92.197 255.255.255.0\n no shutdown\n!'</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 1     | <ul><li>'Default usernames such as admin or root should be changed || ! RTR-12-6 Configuration\n!\nhostname RTR-12-6\nversion 15.7\nusername sysadmin privilege 15 secret 5 $1$7102$hash\ninterface GigabitEthernet0/1\n ip address 164.201.38.152 255.255.255.0\n no shutdown\n!'</li><li>'Default usernames such as admin or root should be changed || ! Generated: 2024-01-22\n!\nhostname RTR-17-76\nversion 15.7\nusername devops privilege 15 secret 5 $1$1152$hash'</li><li>'Default usernames such as admin or root should be changed || # -*- restclient -*-\n\n# Settings\n:node = asr-101\n:addr = 50.196.141.39\n:deviceusername = <username>\n:devicepassword = <password>\n:host = http://localhost:8181\n:basic-auth := (format "Basic %s" (base64-encode-string (format "%s:%s" "admin" "admin")))\n\n# Create ASR 101\nPOST :host/restconf/config/network-topology:network-topology/topology/topology-netconf/node/controller-config/yang-ext:mount/config:modules\nAuthorization: :basic-auth\nContent-Type: application/xml\n<module xmlns="urn:opendaylight:params:xml:ns:yang:controller:config">\n   <type xmlns:prefix="urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf">prefix:sal-netconf-connector</type>\n   <name>:node\n   </name>\n   <address xmlns="urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf">:addr\n   </address>\n   <port xmlns="urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf">830</port>\n   <username xmlns="urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf">:deviceusername</username>\n   <password xmlns="urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf">:devicepassword</password>\n   <tcp-only xmlns="urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf">false</tcp-only>\n   <event-executor xmlns="urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf">\n     <type xmlns:prefix="urn:opendaylight:params:xml:ns:yang:controller:netty">prefix:netty-event-executor</type>\n     <name>global-event-executor</name>\n   </event-executor>\n   <binding-registry xmlns="urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf">\n     <type xmlns:prefix="urn:opendaylight:params:xml:ns:yang:controller:md:sal:binding">prefix:binding-broker-osgi-registry</type>\n     <name>binding-osgi-broker</name>\n   </binding-registry>\n   <dom-registry xmlns="urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf">\n     <type xmlns:prefix="urn:opendaylight:params:xml:ns:yang:controller:md:sal:dom">prefix:dom-broker-osgi-registry</type>\n     <name>dom-broker</name>\n   </dom-registry>\n   <client-dispatcher xmlns="urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf">\n     <type xmlns:prefix="urn:opendaylight:params:xml:ns:yang:controller:config:netconf">prefix:netconf-client-dispatcher</type>\n     <name>global-netconf-dispatcher</name>\n   </client-dispatcher>\n   <processing-executor xmlns="urn:opendaylight:params:xml:ns:yang:controller:md:sal:connector:netconf">\n     <type xmlns:prefix="urn:opendaylight:params:xml:ns:yang:controller:threadpool">prefix:threadpool</type>\n     <name>global-netconf-processing-executor</name>\n   </processing-executor>\n </module>\n\n# Get node operational status\nGET :host/restconf/operational/network-topology:network-topology/topology/topology-netconf/node/:node/\nAuthorization: :basic-auth\n\n# Get interface configuration\nGET :host/restconf/operational/network-topology:network-topology/topology/topology-netconf/node/:node/yang-ext:mount/Cisco-IOS-XR-ifmgr-cfg:interface-configurations/\nAuthorization: :basic-auth\nAccept: application/xml\n\n# Get operational l2vpn xconnect groups\nGET :host/restconf/operational/network-topology:network-topology/topology/topology-netconf/node/:node/yang-ext:mount/Cisco-IOS-XR-l2vpn-cfg:l2vpn/database/xconnect-groups/xconnect-group/local\nAuthorization: :basic-auth\nAccept: application/xml\n\n# Show\nGET :host/restconf/config/network-topology:network-topology/topology/topology-netconf/node/controller-config/yang-ext:mount/config:modules/module/odl-sal-netconf-connector-cfg:sal-netconf-connector/:node\nAuthorization: :basic-auth\n\n# Delete\nDELETE :host/restconf/config/network-topology:network-topology/topology/topology-netconf/node/controller-config/yang-ext:mount/config:modules/module/odl-sal-netconf-connector-cfg:sal-netconf-connector/:node\nAuthorization: :basic-auth'</li></ul> |

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
preds = model("Default usernames such as admin or root should be changed || ! Generated: 2024-01-18
!
hostname RTR-13-7
version 15.7
username guest privilege 15 secret 5 $1$3516$hash")
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
| Word count   | 7   | 46.4031 | 384 |

| Label | Training Sample Count |
|:------|:----------------------|
| 0     | 472                   |
| 1     | 446                   |

### Training Hyperparameters
- batch_size: (8, 8)
- num_epochs: (2, 5)
- max_steps: 500
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
- max_length: 256
- seed: 42
- eval_max_steps: -1
- load_best_model_at_end: False

### Training Results
| Epoch | Step | Training Loss | Validation Loss |
|:-----:|:----:|:-------------:|:---------------:|
| 0.002 | 1    | 0.2452        | -               |
| 0.1   | 50   | 0.2857        | -               |
| 0.2   | 100  | 0.2740        | -               |
| 0.3   | 150  | 0.2548        | -               |
| 0.4   | 200  | 0.2578        | -               |
| 0.5   | 250  | 0.2520        | -               |
| 0.6   | 300  | 0.2560        | -               |
| 0.7   | 350  | 0.2572        | -               |
| 0.8   | 400  | 0.2641        | -               |
| 0.9   | 450  | 0.2605        | -               |
| 1.0   | 500  | 0.2546        | 0.2521          |

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