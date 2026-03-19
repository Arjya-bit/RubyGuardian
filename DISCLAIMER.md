# Legal and Ethical Disclaimer

## IMPORTANT — READ BEFORE USE

RubyGuardian is a **security research and educational framework** developed
exclusively for academic study, authorized penetration testing, and controlled
laboratory environments.

## Intended Use

This software is designed for:

1. **Academic Research**: Studying Ruby-specific attack vectors and developing
   corresponding defenses as part of formal academic programs.

2. **Authorized Security Testing**: Conducting penetration tests and red team
   exercises with explicit written authorization from system owners.

3. **Security Tool Development**: Building and validating detection mechanisms,
   forensic analysis tools, and machine learning classifiers.

4. **Education and Training**: Teaching cybersecurity concepts through hands-on
   labs in controlled environments.

## Prohibited Use

You **must not** use this software to:

- Attack, compromise, or disrupt systems you do not own or have explicit
  authorization to test
- Create, distribute, or deploy malware
- Conduct unauthorized surveillance or data collection
- Violate any applicable local, state, national, or international laws
- Cause harm to individuals, organizations, or infrastructure

## User Responsibility

By downloading, installing, or using any component of this framework, you
acknowledge and agree that:

1. You are solely responsible for ensuring your use complies with all
   applicable laws and regulations.
2. The authors and contributors bear no responsibility for misuse.
3. All attack simulations must be conducted in isolated, controlled environments.
4. You will not deploy any attack component against unauthorized targets.
5. You understand the techniques demonstrated and will use this knowledge
   only for defensive purposes.

## Safe Defaults

All attack components are configured with safe defaults:

- Payloads perform benign operations (spawning calculator, running `id`)
- Network operations default to localhost (127.0.0.1)
- C2 communications are restricted to isolated Docker networks
- Honeypots operate in receive-only mode
- All destructive operations require explicit confirmation

## Liability

THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN NO EVENT
SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES ARISING FROM THE USE OF THIS SOFTWARE.

## Contact

For questions about responsible use, contact the project maintainers.
