NAS Seed Corpus
==============
Contains valid NAS-5GS message samples as hex-encoded PDUs.
These are loaded by the fuzzing engine as initial seeds.

Messages:
  - registration_request.bin: Initial registration (5GMM Registration Request)
  - service_request.bin: Service request (5GMM Service Request)
  - pdu_session_est_req.bin: PDU Session Establishment Request (5GSM)

Add additional seeds by placing hex-encoded binary files here.
Each file should contain one complete NAS-5GS PDU.
