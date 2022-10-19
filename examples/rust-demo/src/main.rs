/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use provide_rust::api::{client::ApiClient, ident::{Ident, User}, baseline::{Baseline, Workflow, Workstep}};
use serde_json::{json, Value, to_string_pretty};

#[tokio::main]
async fn main() {

    let ident: ApiClient = Ident::factory("eyJhbGciOiJSUzI1NiIsImtpZCI6ImM1OmViOjhkOjU5OjQ0OjM4OjYzOjA2OmM5OmQzOmU0Ojk3OjA4OmZiOjY4OjljIiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL2lkZW50LnByb3ZpZGUuc2VydmljZXMvYXBpL3YxIiwiZXhwIjoxNjQwODQxMTI3LCJpYXQiOjE2NDA3NTQ3MjcsImlzcyI6Imh0dHBzOi8vaWRlbnQucHJvdmlkZS5zZXJ2aWNlcyIsImp0aSI6ImQ1NTg1Y2QzLWRhMzUtNGRkNy1iNzgyLWIyMTJhZjVkNDY2NiIsIm5hdHMiOnsicGVybWlzc2lvbnMiOnsicHVibGlzaCI6eyJhbGxvdyI6WyJiYXNlbGluZSIsImJhc2VsaW5lLlx1MDAzZSJdfSwic3Vic2NyaWJlIjp7ImFsbG93IjpbInVzZXIuMDE5YzI0NmQtY2MwMS00NzY5LWI0OWEtZGM3YzA3MzQ1OTcxIiwiYmFzZWxpbmUiLCJiYXNlbGluZS5cdTAwM2UiLCJuZXR3b3JrLiouY29ubmVjdG9yLioiLCJuZXR3b3JrLiouY29udHJhY3RzLioiLCJuZXR3b3JrLiouc3RhdHVzIiwicGxhdGZvcm0uXHUwMDNlIl19fX0sInBydmQiOnsicGVybWlzc2lvbnMiOjQxNSwidXNlcl9pZCI6IjAxOWMyNDZkLWNjMDEtNDc2OS1iNDlhLWRjN2MwNzM0NTk3MSJ9LCJzdWIiOiJ1c2VyOjAxOWMyNDZkLWNjMDEtNDc2OS1iNDlhLWRjN2MwNzM0NTk3MSJ9.cOchnGw2mkR7JuUBdqWe_k36A89jUSU7gF1DkYyarb3RihOAXC_gp3xvj87p_Zp38XHbNdxfAWk60LgFJ9s1mh0dsO_gWt5jHeI8Mte6Z21PGnoyMcxk_mEM522KWMBKhhBwlc33AvrdU8ef18KzGQg1_qJtrOLnogrw5xbv6feoVRXc5LgRyJ18WWD5xSVyaSDLp8RR-SJ9U5RLE2lz3684IyM9RESrY9aG7agz9BL3Zh1ucO2nhEG-Ed60L9ZUWEec6TtgoV07CfaX4PiOIfRyuJpJ63uGY0cke4iZGPLxdjjapRJbmmDlAt6-WjJvNJeeBzVRXVp2J1VmScdmo0xOYlYBxvYRb_t8T2aBJO3B5Um41cECBxkWPEHoXlIAdgpHyBX13sG4Cmwm8fh-Fm_7glsHaooXfAjkAYUTAD96186xnNzmZxF8KvqN_XNkJdAOoN_pD2Hcfm5Na4d6l-CUH4_YRkccPqaScJb1oJ63MvomaOomS3qcS51etNpe1DSThHFx0iQAA9MztBk-uynCCxoqYvmZxaFuFcy3iwEeSspD0qk3p7nQdmtdQla96K5i4m0Lk-EEbCaa6ec_yJmzN42fJPK9tdHFzzwEKMmlBtp0O15NUCfWtPEINdbe61ttZdLWl5luq4xFDt5pGiNnRv85htCwXM40Xh4tIcE");

    let organization = ident.get_organization("863c47a1-5b8c-43f1-9387-00298283c0a5").await.unwrap();
    let workgroup = ident.get_application("79a80507-23b7-45e5-9a05-538481e7623c").await.unwrap();
    println!("Organization {}\n", to_string_pretty(&organization.json::<Value>().await.unwrap()).unwrap());
    println!("Workgroup {}\n", to_string_pretty(&workgroup.json::<Value>().await.unwrap()).unwrap());


    // initialize ident client with empty access token
    let baseline: ApiClient = Baseline::factory("eyJhbGciOiJSUzI1NiIsImtpZCI6ImM1OmViOjhkOjU5OjQ0OjM4OjYzOjA2OmM5OmQzOmU0Ojk3OjA4OmZiOjY4OjljIiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL2lkZW50LnByb3ZpZGUuc2VydmljZXMvYXBpL3YxIiwiZXhwIjoxNjQwODQxMTI3LCJpYXQiOjE2NDA3NTQ3MjcsImlzcyI6Imh0dHBzOi8vaWRlbnQucHJvdmlkZS5zZXJ2aWNlcyIsImp0aSI6ImZiZWRmZmIxLTNlOWItNDczZi04MmJkLWY2ZWY3NGU1ZWZlNiIsIm5hdHMiOnsicGVybWlzc2lvbnMiOnsicHVibGlzaCI6eyJhbGxvdyI6WyJiYXNlbGluZSIsImJhc2VsaW5lLlx1MDAzZSJdfSwic3Vic2NyaWJlIjp7ImFsbG93IjpbInVzZXIuMDE5YzI0NmQtY2MwMS00NzY5LWI0OWEtZGM3YzA3MzQ1OTcxIiwib3JnYW5pemF0aW9uLjg2M2M0N2ExLTViOGMtNDNmMS05Mzg3LTAwMjk4MjgzYzBhNSIsImJhc2VsaW5lIiwiYmFzZWxpbmUuXHUwMDNlIiwibmV0d29yay4qLmNvbm5lY3Rvci4qIiwibmV0d29yay4qLmNvbnRyYWN0cy4qIiwibmV0d29yay4qLnN0YXR1cyIsInBsYXRmb3JtLlx1MDAzZSJdfX19LCJwcnZkIjp7Im9yZ2FuaXphdGlvbl9pZCI6Ijg2M2M0N2ExLTViOGMtNDNmMS05Mzg3LTAwMjk4MjgzYzBhNSIsInBlcm1pc3Npb25zIjo1MTAsInVzZXJfaWQiOiIwMTljMjQ2ZC1jYzAxLTQ3NjktYjQ5YS1kYzdjMDczNDU5NzEifSwic3ViIjoib3JnYW5pemF0aW9uOjg2M2M0N2ExLTViOGMtNDNmMS05Mzg3LTAwMjk4MjgzYzBhNSJ9.U00qHOwjFJFGIC4rn2It_J2ahFJ0CCBoobVvy9RyPwph813uYDH8AfR35PW8-S--v45yY_RY_gWmJMrXy3TbxMC20i-WXibsOXYDFCxAf1WGfZmBFjpVhEo1KlMwCnwC2FzeU0C5phYFoH5Fg82jlxNf-gsyHiHyKIZOGKnRO2UYIdymN5Ek3hnQeCL1IoxaSBZhYfQE8-S0AlG-AuWqLf7mWI2VYbhVLKWmTQA1VjpnWCsZawjIxolo7RlbMwUgAmbNUZXpSHL-JAuSeRfMVhEvck-WPVdr761HUI8CBB09apYKrL9-GLnzk90Jq_sd14vznGbdYUalnjt3h7rCs7VIhNJXKmrl4tTf7XpZEyIOd0EtGehhj9FB-j9K1tHZF_MQ7GT7O53YjiJv5MUkjjUVqf89XhbMBWqFmmS4YQC3W0oD7b0PkDm0OcjAiA28jrspFfSBQcVTmrgA6eEkafpXB6QipBpe2WoPBN-RqVs4ZbCadUj44vVEy7E5ZQhGjVc6Wr93OppyOvA7yijtYpYZbbjdOEoFsF8ckDeMtZ9h4XTRjjal5moxEUXmaIuAqxpRkX6t-ZH6Gh5SkmCb5N8dTSOBRS5qTK7PfgQwwgxbZTdgj-aV7jxdkvdawKN_ACBaA_n3A76iGCGsmmpiAXeGjPvRHjNg-CCyt8OJ2y0");

    // create user request body
    let create_workflow_params = json!({
        "workgroup_id": "79a80507-23b7-45e5-9a05-538481e7623c",
        "name": "some workflow 4",
        "version": "1",
    });

    let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");

    // deserialize into Ident User struct
    let workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");
    println!("Workflow {}\n", to_string_pretty(&workflow_body).unwrap());

    let create_workstep_params = json!({
        "name": "first workstep",
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "cubic groth16",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
        },
    });

    let create_workstep_res = baseline.create_workstep(&workflow_body.id, Some(create_workstep_params)).await.expect("create workstep response");

    let workstep_body = create_workstep_res.json::<Value>().await.expect("create workstep body");
    println!("Workstep {}\n", to_string_pretty(&workstep_body).unwrap());

    let deploy_workflow_res = baseline.deploy_workflow(&workflow_body.id).await.expect("create workflow res");
    assert_eq!(deploy_workflow_res.status(), 202);
}

// add tests
