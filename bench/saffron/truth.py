"""Answer key for the Saffron Bank pack (written by us from the pack README + value samples, before tuning anything).
S = sensitive: must be masked from non-admin roles. Q = personal attribute or quasi-identifier: masking is right, not
masking is a judgement call. N = not personal (keys, codes, dates, statuses, the bank's own branch data)."""
S, Q, N = "S", "Q", "N"
TRUTH = {
 "branches": dict(branch_code=N, ifsc=N, branch_nm=N, addr=N, city=N, state=N, pincode=N, branch_phone=N, branch_email=N,
                  region=N, opened_on=N),
 "customers": dict(customer_id=N, cust_nm=S, gender=Q, dob_dt=S, mob_no=S, emailid=S, addr_line1=S, addr_line2=S, city=Q,
                   state=N, pincode=Q, pita_nm=S, alt_mob=S, occupation=Q, segment=N, risk_cat=Q, home_branch=N,
                   customer_since=N, preferred_lang=N, last_login_ts=N),
 "kyc_records": dict(kyc_id=N, customer_id=N, pan_no=S, aadhaar_no=S, ovd_type=N, kyc_status=N, kyc_mode=N, verified_on=N,
                     verified_by=N, next_review_dt=N, kyc_meta=Q),
 "international_customers": dict(customer_id=N, ssn=S, us_addr=S, us_city=Q, us_state=N, us_zip=Q, us_phone=S,
                                 residency_status=Q, fatca_flag=N, tax_form=N, tin_country=N, fatca_reported_on=N),
 "accounts": dict(account_no=S, customer_id=N, branch_code=N, ifsc=N, acct_type=N, curr_bal=S, open_dt=N, acct_status=N,
                  nominee_nm=S, nominee_rel=Q, od_limit_inr=S, int_rate_pct=N, extra_info=S, last_txn_dt=N),
 "cards": dict(CARD_REF=N, CUSTOMER_ID=N, LINKED_ACCT=S, CARD_NO=S, CARD_NETWORK=N, CARD_TYPE=N, CARD_VARIANT=N,
               NAME_ON_CARD=S, EXP_MM=Q, EXP_YYYY=Q, CREDIT_LIMIT=S, OUTSTANDING_AMT=S, CARD_STATUS=N, ISSUED_ON=N),
 "transactions": dict(txn_id=N, account_no=S, txn_ts=N, amount_inr=S, dr_cr=N, channel=N, counterparty=Q, narration=S,
                      ref_no=N, rrn=N, bal_after=S, txn_status=N),  # ref_no: card-shaped decoys that fail Luhn; README: references are random
 "support_tickets": dict(ticket_id=N, customer_id=N, created_ts=N, channel=N, category=N, priority=N, ticket_text=S, notes=S,
                         status=N, resolved_ts=N, assigned_to=N),
 "loan_applications": dict(app_id=N, customer_id=N, loan_type=N, applied_on=N, amt_requested_inr=S, tenure_mths=N,
                           declared_income_inr=S, employer_nm=Q, emp_type=N, credit_score=S, decision=N,
                           sanctioned_amt_inr=S, roi_pct=N, col_7=S, remarks=S),
}
