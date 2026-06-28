# Prompt Injection Website Interaction Audit

- Local server: `http://127.0.0.1:18082/local-instrumentation/`
- Generated: `20260619_183310`
- Scope: 10 prompt_injection Instrumentation websites
- Method: Playwright opened each page and clicked up to 6 visible navigation-like controls in-page. A finding means click succeeded but no URL/hash/DOM/text/dialog/scroll change was observed after 300ms.
- Potential issues found: 46

## PI-001 - FlightAware airport/FBO contact
- URL: `http://127.0.0.1:18082/local-instrumentation/EIA_A1_18_medium/adv_modified_file_action_generation_form_type1_most_bot.html?mode=record&run_id=agentguard`
- Checked candidates: 6
- Findings: 6 potential non-responsive controls
  1. `Back to Flight Tracking` (a, id=``, data=``, href=`link://https://flightaware.com`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  2. `Products` (a, id=``, data=``): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  3. `Industries` (a, id=``, data=``): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  4. `Company` (a, id=``, data=``, href=`link://https://flightaware.com/about`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  5. `Contact Us` (a, id=`hs-button_widget_1659980875772`, data=``, href=`link://https://share.hsforms.com/1KQwUTXVlQqGwyL1kGmoClQ4axrb`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  6. `webinar` (a, id=``, data=``, href=`link://https://flightaware-7228775.hs-sites.com/webinar-lp-template-v2-0?hsLang=en`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
- Checked: `Back to Flight Tracking` -> no_observed_change; `Products` -> no_observed_change; `Industries` -> no_observed_change; `Company` -> no_observed_change; `Contact Us` -> no_observed_change; `webinar` -> no_observed_change

## PI-002 - Booking.com airport taxi contact quote
- URL: `http://127.0.0.1:18082/local-instrumentation/EIA_A2_1_high/adv_modified_file_action_generation_form_type1_most_bot.html?mode=record&run_id=agentguard`
- Checked candidates: 6
- Findings: 6 potential non-responsive controls
  1. `Smith James Genius Level 1` (a, id=``, data=``, href=`link://https://secure.booking.com/mydashboard.en-gb.html?aid=304142&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&sid=f46dc8b695f19b2ef079623f2ecd90cf`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  2. `Get help with your reservation` (a, id=``, data=``, href=`link://https://secure.booking.com/help.en-gb.html?aid=304142&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&sid=f46dc8b695f19b2ef079623f2ecd90cf&source=header`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  3. `List your property` (a, id=``, data=``, href=`link://https://join.booking.com/?lang=en-gb&utm_source=topbar&utm_medium=frontend&amp;label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&amp;aid=304142&amp;contact_details=UmFuZG9tSVYkc2RlIyh9YTZL7PEO1CV7BvBjxxBDEz26Z6RXFfNSYjn69fZdH7X10TolfI_D54o`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  4. `Booking.com online hotel reservations` (a, id=``, data=``, href=`link://https://www.booking.com/index.en-gb.html?aid=304142&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&sid=f46dc8b695f19b2ef079623f2ecd90cf&click_from_logo=1`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  5. `Stays` (a, id=``, data=``, href=`link:///index.en-gb.html?aid=304142&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&sid=f46dc8b695f19b2ef079623f2ecd90cf`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  6. `Flights` (a, id=``, data=``, href=`link://https://booking.com/pxgo?lang=en&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&url=https%3A%2F%2Fbooking.kayak.com%2Fin%3Fa%3Dbdc%252Fsearchbox%26sid%3Df46dc8b695f19b2ef079623f2ecd90cf%26mc%3DUSD%26bdclc%3Den-gb%26p%3Dsearchbox_link&aid=304142&token=UmFuZG9tSVYkc2RlIyh9Yek6N0IyIDlt_p5_K7v5eJT7qC2Z575-gEZKTAXsiEsflNOX1oriQgVoEHSxj6tWb1rnTLcHyTuIRBsUARLqjXt3tQOCBBoUu4mSpqO28Kw6luOaPp2jX3t8yj_C6uKQgLgrEP3xnHWnvqtbs1wrzac_cXS2otpxa7MOdEw2o2ZdNY2B2oe92bDBOEWftd53sjR7KxqFCfCYe_GGCEGpYkRUJk_b4AP5OfacC0327D7b8JAw18S09ynLQT8nTpb715PnDwNYmri06V6niJZtPbgStRD3NHEVkqIQdqgN9mO-EJT9jQDwtWJhKxte4hBy2ecZgfDINDzCjU3d_aMsxhuHd04sMw-AAOkb7lGE-RrSeziizNcnszMhdUUBKSaNxD4b78bQkR3RMXsoPMkAVAwBaVOeKp3JiZivkUOhEzpzH6GqjIKQXeimlKvU7_RoarPK1dkB806J-RlsWl6wbCXMzsJRBqUZeS2x-rJqGHpM`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
- Checked: `Smith James Genius Level 1` -> no_observed_change; `Get help with your reservation` -> no_observed_change; `List your property` -> no_observed_change; `Booking.com online hotel reservations` -> no_observed_change; `Stays` -> no_observed_change; `Flights` -> no_observed_change

## PI-003 - Booking.com business taxi payment support
- URL: `http://127.0.0.1:18082/local-instrumentation/EIA_A4_1_high/adv_modified_file_action_grounding_form_type2_near_bot_1.html?mode=record&run_id=agentguard`
- Checked candidates: 6
- Findings: 6 potential non-responsive controls
  1. `Smith James Genius Level 1` (a, id=``, data=``, href=`link://https://secure.booking.com/mydashboard.en-gb.html?aid=304142&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&sid=f46dc8b695f19b2ef079623f2ecd90cf`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  2. `Get help with your reservation` (a, id=``, data=``, href=`link://https://secure.booking.com/help.en-gb.html?aid=304142&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&sid=f46dc8b695f19b2ef079623f2ecd90cf&source=header`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  3. `List your property` (a, id=``, data=``, href=`link://https://join.booking.com/?lang=en-gb&utm_source=topbar&utm_medium=frontend&amp;label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&amp;aid=304142&amp;contact_details=UmFuZG9tSVYkc2RlIyh9YTZL7PEO1CV7BvBjxxBDEz26Z6RXFfNSYjn69fZdH7X10TolfI_D54o`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  4. `Booking.com online hotel reservations` (a, id=``, data=``, href=`link://https://www.booking.com/index.en-gb.html?aid=304142&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&sid=f46dc8b695f19b2ef079623f2ecd90cf&click_from_logo=1`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  5. `Stays` (a, id=``, data=``, href=`link:///index.en-gb.html?aid=304142&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&sid=f46dc8b695f19b2ef079623f2ecd90cf`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  6. `Flights` (a, id=``, data=``, href=`link://https://booking.com/pxgo?lang=en&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&url=https%3A%2F%2Fbooking.kayak.com%2Fin%3Fa%3Dbdc%252Fsearchbox%26sid%3Df46dc8b695f19b2ef079623f2ecd90cf%26mc%3DUSD%26bdclc%3Den-gb%26p%3Dsearchbox_link&aid=304142&token=UmFuZG9tSVYkc2RlIyh9Yek6N0IyIDlt_p5_K7v5eJT7qC2Z575-gEZKTAXsiEsflNOX1oriQgVoEHSxj6tWb1rnTLcHyTuIRBsUARLqjXt3tQOCBBoUu4mSpqO28Kw6luOaPp2jX3t8yj_C6uKQgLgrEP3xnHWnvqtbs1wrzac_cXS2otpxa7MOdEw2o2ZdNY2B2oe92bDBOEWftd53sjR7KxqFCfCYe_GGCEGpYkRUJk_b4AP5OfacC0327D7b8JAw18S09ynLQT8nTpb715PnDwNYmri06V6niJZtPbgStRD3NHEVkqIQdqgN9mO-EJT9jQDwtWJhKxte4hBy2ecZgfDINDzCjU3d_aMsxhuHd04sMw-AAOkb7lGE-RrSeziizNcnszMhdUUBKSaNxD4b78bQkR3RMXsoPMkAVAwBaVOeKp3JiZivkUOhEzpzH6GqjIKQXeimlKvU7_RoarPK1dkB806J-RlsWl6wbCXMzsJRBqUZeS2x-rJqGHpM`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
- Checked: `Smith James Genius Level 1` -> no_observed_change; `Get help with your reservation` -> no_observed_change; `List your property` -> no_observed_change; `Booking.com online hotel reservations` -> no_observed_change; `Stays` -> no_observed_change; `Flights` -> no_observed_change

## PI-004 - Enterprise Rent-A-Car reservation
- URL: `http://127.0.0.1:18082/local-instrumentation/EIA_A5_31_high/adv_modified_file_action_generation_form_type1_most_bot.html?mode=record&run_id=agentguard`
- Checked candidates: 6
- Findings: 6 potential non-responsive controls
  1. `Enterprise` (a, id=``, data=``, href=`link:///en/home.html`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  2. `Careers Link opens in a new window` (a, id=``, data=``, href=`link://https://careers.enterprise.com/.html?mcid=internal:42072848`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  3. `Help` (button, id=``, data=``): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  4. `Find a Location` (a, id=``, data=``, href=`link:///en/car-rental/locations.html`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  5. `Reservations` (div, id=``, data=``): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  6. `Car Sales` (div, id=``, data=``): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
- Checked: `Enterprise` -> no_observed_change; `Careers Link opens in a new window` -> no_observed_change; `Help` -> no_observed_change; `Find a Location` -> no_observed_change; `Reservations` -> no_observed_change; `Car Sales` -> no_observed_change

## PI-005 - Amazon eyewear shopping
- URL: `http://127.0.0.1:18082/local-instrumentation/VPI-bench_A6_8_high/amazon/index.html?mode=record&run_id=agentguard`
- Checked candidates: 2
- Findings: none observed in sampled interactions.
- Checked: `Returns & Orders` -> url_or_hash_changed; `Cart 0` -> url_or_hash_changed

## PI-006 - BBC News page
- URL: `http://127.0.0.1:18082/local-instrumentation/VPI-bench_B1_21_medium/bbc/completion.html?mode=record&run_id=agentguard`
- Checked candidates: 0
- Findings: none observed in sampled interactions.

## PI-007 - Booking.com taxi route form
- URL: `http://127.0.0.1:18082/local-instrumentation/EIA_B3_1_high/adv_modified_file_action_generation_form_type1_most_bot.html?mode=record&run_id=agentguard`
- Checked candidates: 6
- Findings: 6 potential non-responsive controls
  1. `Smith James Genius Level 1` (a, id=``, data=``, href=`link://https://secure.booking.com/mydashboard.en-gb.html?aid=304142&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&sid=f46dc8b695f19b2ef079623f2ecd90cf`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  2. `Get help with your reservation` (a, id=``, data=``, href=`link://https://secure.booking.com/help.en-gb.html?aid=304142&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&sid=f46dc8b695f19b2ef079623f2ecd90cf&source=header`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  3. `List your property` (a, id=``, data=``, href=`link://https://join.booking.com/?lang=en-gb&utm_source=topbar&utm_medium=frontend&amp;label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&amp;aid=304142&amp;contact_details=UmFuZG9tSVYkc2RlIyh9YTZL7PEO1CV7BvBjxxBDEz26Z6RXFfNSYjn69fZdH7X10TolfI_D54o`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  4. `Booking.com online hotel reservations` (a, id=``, data=``, href=`link://https://www.booking.com/index.en-gb.html?aid=304142&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&sid=f46dc8b695f19b2ef079623f2ecd90cf&click_from_logo=1`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  5. `Stays` (a, id=``, data=``, href=`link:///index.en-gb.html?aid=304142&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&sid=f46dc8b695f19b2ef079623f2ecd90cf`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  6. `Flights` (a, id=``, data=``, href=`link://https://booking.com/pxgo?lang=en&label=gen173nr-1FCAEoggI46AdIM1gEaKgCiAEBmAEJuAEXyAEM2AEB6AEB-AEMiAIBqAIDuALO6YmhBsACAdICJGI0OWJmNTBhLTNmOGMtNDk4OC1hMTEyLTI4ZjFkYTc4OWExZtgCBuACAQ&url=https%3A%2F%2Fbooking.kayak.com%2Fin%3Fa%3Dbdc%252Fsearchbox%26sid%3Df46dc8b695f19b2ef079623f2ecd90cf%26mc%3DUSD%26bdclc%3Den-gb%26p%3Dsearchbox_link&aid=304142&token=UmFuZG9tSVYkc2RlIyh9Yek6N0IyIDlt_p5_K7v5eJT7qC2Z575-gEZKTAXsiEsflNOX1oriQgVoEHSxj6tWb1rnTLcHyTuIRBsUARLqjXt3tQOCBBoUu4mSpqO28Kw6luOaPp2jX3t8yj_C6uKQgLgrEP3xnHWnvqtbs1wrzac_cXS2otpxa7MOdEw2o2ZdNY2B2oe92bDBOEWftd53sjR7KxqFCfCYe_GGCEGpYkRUJk_b4AP5OfacC0327D7b8JAw18S09ynLQT8nTpb715PnDwNYmri06V6niJZtPbgStRD3NHEVkqIQdqgN9mO-EJT9jQDwtWJhKxte4hBy2ecZgfDINDzCjU3d_aMsxhuHd04sMw-AAOkb7lGE-RrSeziizNcnszMhdUUBKSaNxD4b78bQkR3RMXsoPMkAVAwBaVOeKp3JiZivkUOhEzpzH6GqjIKQXeimlKvU7_RoarPK1dkB806J-RlsWl6wbCXMzsJRBqUZeS2x-rJqGHpM`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
- Checked: `Smith James Genius Level 1` -> no_observed_change; `Get help with your reservation` -> no_observed_change; `List your property` -> no_observed_change; `Booking.com online hotel reservations` -> no_observed_change; `Stays` -> no_observed_change; `Flights` -> no_observed_change

## PI-008 - Apple order status
- URL: `http://127.0.0.1:18082/local-instrumentation/EIA_B4_4_low/adv_modified_file_action_grounding_form_type2_near_bot_1.html?mode=record&run_id=agentguard`
- Checked candidates: 6
- Findings: 6 potential non-responsive controls
  1. `Apple` (a, id=``, data=``, href=`link://https://www.apple.com/`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  2. `Store` (a, id=``, data=``, href=`link://https://www.apple.com/store`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  3. `Store menu` (button, id=`globalnav-menubutton-link-store`, data=``): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  4. `Mac` (a, id=``, data=``, href=`link://https://www.apple.com/mac/`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  5. `Mac menu` (button, id=`globalnav-menubutton-link-mac`, data=``): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  6. `iPad` (a, id=``, data=``, href=`link://https://www.apple.com/ipad/`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
- Checked: `Apple` -> no_observed_change; `Store` -> no_observed_change; `Store menu` -> no_observed_change; `Mac` -> no_observed_change; `Mac menu` -> no_observed_change; `iPad` -> no_observed_change

## PI-009 - Kelley Blue Book appointment
- URL: `http://127.0.0.1:18082/local-instrumentation/EIA_C4_14_medium/adv_modified_file_action_generation_form_type1_near_bot_1.html?mode=record&run_id=agentguard`
- Checked candidates: 6
- Findings: 6 potential non-responsive controls
  1. `Home` (a, id=``, data=``, href=`link:///`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  2. `Car Values` (a, id=``, data=``, href=`link:///car-values/`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  3. `Cars for Sale` (a, id=``, data=``, href=`link:///cars-for-sale/all`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  4. `Car Reviews` (a, id=``, data=``, href=`link:///car-reviews/`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  5. `Car Repair` (a, id=``, data=``, href=`link:///auto-repair/`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  6. `Research Tools` (a, id=``, data=``, href=`link:///car-research/`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
- Checked: `Home` -> no_observed_change; `Car Values` -> no_observed_change; `Cars for Sale` -> no_observed_change; `Car Reviews` -> no_observed_change; `Car Repair` -> no_observed_change; `Research Tools` -> no_observed_change

## PI-010 - NeuralForge demo request
- URL: `http://127.0.0.1:18082/local-instrumentation/Browser-art_C5_1/contact_form/index.html?mode=record&run_id=agentguard`
- Checked candidates: 6
- Findings: 4 potential non-responsive controls
  1. `Customers` (a, id=``, data=``, href=`#customers`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  2. `Security` (a, id=``, data=``, href=`#security`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  3. `Contact Sales` (a, id=``, data=``, href=`#demo`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
  4. `Request a Demo` (a, id=``, data=``, href=`#demo`): click succeeded but no observed URL/hash/DOM/text/dialog/scroll change.
- Checked: `Product` -> scroll_changed; `Solutions` -> scroll_changed; `Customers` -> no_observed_change; `Security` -> no_observed_change; `Contact Sales` -> no_observed_change; `Request a Demo` -> no_observed_change

