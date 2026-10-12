"""Explicit scope and provenance for ten independent feature scenarios."""
PROJECT = {
    "cases": [
        [
            "Real project README copy and controlled byte mutation",
            "tests.test_portfolio_files.ProjectFileTests.test_actual_readme_copy_and_mutation"
        ],
        [
            "ZIP containing actual project source files",
            "tests.test_portfolio_files.ProjectFileTests.test_zip_of_actual_project_sources"
        ],
        [
            "ZIP parent and absolute path escape indicators",
            "tests.test_zip_risks.ZipRiskTests.test_paths"
        ],
        [
            "ZIP encrypted metadata indicator",
            "tests.test_zip_risks.ZipRiskTests.test_encryption"
        ],
        [
            "Bounded high compression ratio indicator",
            "tests.test_zip_risks.ZipRiskTests.test_ratio"
        ],
        [
            "Local/central ZIP header disagreement",
            "tests.test_zip_risks.ZipRiskTests.test_header_disagreement"
        ],
        [
            "No decompression or extraction during inspection",
            "tests.test_zip_risks.ZipRiskTests.test_no_decompression_or_extraction"
        ],
        [
            "Payload mutation does not imply a CRC check",
            "tests.test_zip_risks.ZipRiskTests.test_crc_not_claimed"
        ],
        [
            "Missing trusted reference is not integrity proof",
            "tests.test_inspection.InspectionTests.test_missing_hash"
        ],
        [
            "Bidirectional filename control indicator",
            "tests.test_inspection.InspectionTests.test_bidi_filename"
        ]
    ],
    "checks": [
        [
            "inspector-browser",
            [
                "tests/browser/smoke.mjs"
            ]
        ]
    ],
    "limitations": [
        "Two portfolio cases use actual tracked project files read locally; other cases use inert generated fixtures.",
        "Locally calculated reference hashes test comparison mechanics, not publisher authenticity.",
        "No malware execution, antivirus verdict, extraction, content CRC verification or download interception is performed.",
        "Windows symbolic-link cases may be skipped when the account lacks the required privilege."
    ]
}

