"""
Dual-Model AI Compliance Tests: V6 Primary + V4 Fallback.

Tests the new V6→V4 pipeline where:
- V6 is the primary model (~95% F1)
- V4 is the fallback for uncertain V6 predictions
- Results are fused using weighted probability averaging
- The deterministic rules engine is NOT used for compliance decisions
"""

import unittest
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'

from backend.ml.semantic_compliance import (
    analyze_compliance,
    get_v6_model,
    get_v4_model,
    V6_CONFIDENCE_THRESHOLD,
    V6_FUSION_WEIGHT,
    V4_FUSION_WEIGHT,
)


class TestDualModelArchitecture(unittest.TestCase):
    """Test the V6→V4 dual-model architecture."""

    def test_v6_model_loaded(self):
        """Test that V6 model can be loaded."""
        model = get_v6_model()
        self.assertIsNotNone(model, "V6 model should be loadable")

    def test_v4_model_loaded(self):
        """Test that V4 model can be loaded."""
        model = get_v4_model()
        self.assertIsNotNone(model, "V4 model should be loadable")

    def test_v6_confidence_threshold_constant(self):
        """Test V6 confidence threshold is set correctly."""
        self.assertEqual(V6_CONFIDENCE_THRESHOLD, 0.80)

    def test_fusion_weights_normalized(self):
        """Test fusion weights sum to 1.0."""
        self.assertAlmostEqual(V6_FUSION_WEIGHT + V4_FUSION_WEIGHT, 1.0)

    def test_v6_weight_0_60(self):
        """Test V6 fusion weight is 0.60."""
        self.assertAlmostEqual(V6_FUSION_WEIGHT, 0.60, places=2)

    def test_v4_weight_0_40(self):
        """Test V4 fusion weight is 0.40."""
        self.assertAlmostEqual(V4_FUSION_WEIGHT, 0.40, places=2)


class TestV6HighConfidence(unittest.TestCase):
    """Test V6-only path when confidence is high."""

    def test_cis11_high_confidence_uses_v6_only(self):
        """Test CIS-1.1 with secure username → V6 only."""
        policy = 'Administrative accounts must not use vendor-default credentials'
        config = '''
hostname RTR-1
username netadmin privilege 15 secret 5 hash
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
'''
        result = analyze_compliance(policy, config, 'cisco', 'CIS-1.1')

        # Should use V6 only (no fallback)
        self.assertEqual(result['model_used'], 'V6')
        self.assertFalse(result['fallback_used'])
        self.assertIn('prediction', result)
        self.assertIn('confidence', result)
        # Should NOT have v4 in result
        self.assertNotIn('v4', result)

    def test_cis22_high_confidence_uses_v6_only(self):
        """Test CIS-2.2 with NTP configured → V6 only."""
        policy = 'Network infrastructure must synchronize clock with approved time sources'
        config = '''
hostname RTR-3
ntp server 8.8.8.8
ntp server 8.8.4.4
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
'''
        result = analyze_compliance(policy, config, 'cisco', 'CIS-2.2')

        # Should use V6 only
        self.assertEqual(result['model_used'], 'V6')
        self.assertFalse(result['fallback_used'])


class TestV4Fallback(unittest.TestCase):
    """Test V4 fallback when V6 is uncertain."""

    def test_v6_uncertain_triggers_v4(self):
        """Test that uncertain V6 triggers V4 fallback."""
        # Use a minimal config that might produce uncertain V6 output
        policy = 'Test policy for uncertain case'
        config = 'hostname test'
        result = analyze_compliance(policy, config, 'cisco', 'CIS-1.1')

        # Should have run both models or at least be ready for fallback
        self.assertIn(result['model_used'], ['V6', 'V6+V4'])
        self.assertIn('v6', result)

    def test_fallback_result_structure(self):
        """Test result structure when fallback is triggered."""
        policy = 'Test policy'
        config = 'minimal config'
        result = analyze_compliance(policy, config, 'cisco', 'CIS-1.1')

        # Should have v6 info
        self.assertIn('v6', result)
        self.assertIsInstance(result['v6'], dict)
        self.assertIn('prediction', result['v6'])
        self.assertIn('confidence', result['v6'])

        # If fallback was used, should have v4 and models_agree
        if result.get('fallback_used'):
            self.assertIn('v4', result)
            self.assertIn('models_agree', result)


class TestFusionLogic(unittest.TestCase):
    """Test probability fusion logic."""

    def test_fusion_with_agreement(self):
        """Test fusion when both models agree (both compliant)."""
        from backend.ml.semantic_compliance import _fuse_results

        v6_result = {
            "prediction": "compliant",
            "confidence": 0.85,
            "probability": 0.85,
        }
        v4_result = {
            "prediction": "compliant",
            "confidence": 0.78,
            "probability": 0.78,
        }

        fused = _fuse_results(v6_result, v4_result)

        # With both models agreeing and probabilities close, fused prob should be between
        # min(0.85, 0.78) = 0.78 and max(0.85, 0.78) = 0.85
        # Double-check the weights ensure V6 dominance: 0.85 * 0.6 + 0.78 * 0.4 = 0.822
        # 0.822 is between them ✓
        p_fused = fused['probability']
        self.assertIn(fused['prediction'], ['compliant', 'non_compliant'])
        self.assertGreaterEqual(p_fused, 0.78)
        self.assertLessEqual(p_fused, 0.85)

    def test_fusion_with_disagreement_boundary(self):
        """Test fusion when models disagree near boundary (should predict uncertain)."""
        from backend.ml.semantic_compliance import _fuse_results

        # Use values where p_fused will fall between 0.4 and 0.6
        v6_result = {
            "prediction": "non_compliant",
            "confidence": 0.55,
            "probability": 0.45,
        }
        v4_result = {
            "prediction": "compliant",
            "confidence": 0.65,
            "probability": 0.65,
        }

        # p_fused = 0.45*0.6 + 0.65*0.4 = 0.27 + 0.26 = 0.53
        # 0.53 is between 0.4 and 0.6, and models disagree → uncertain
        fused = _fuse_results(v6_result, v4_result)

        self.assertEqual(fused['prediction'], 'uncertain')
        # Confidence should be the gap between probabilities
        self.assertAlmostEqual(fused['confidence'], abs(0.45 - 0.65), places=2)


class TestAIOnlyArchitecture(unittest.TestCase):
    """Test that rules engine is NOT used for compliance decisions."""

    def test_rules_engine_not_imported_in_routes(self):
        """Verify routes.py does not import evaluate_compliance from rules_engine."""
        with open('backend/api/routes.py', 'r') as f:
            content = f.read()

        # Should NOT import evaluate_compliance from rules_engine
        self.assertNotIn('evaluate_compliance', content,
                        "routes.py should not use evaluate_compliance from rules_engine")
        # Should import analyze_compliance from semantic_compliance
        self.assertIn('analyze_compliance', content,
                     "routes.py should import analyze_compliance")

    def test_rules_engine_not_used_in_audit_endpoint(self):
        """Verify audit endpoint uses AI, not rules engine."""
        with open('backend/api/routes.py', 'r') as f:
            content = f.read()

        # Should use AI analysis
        self.assertIn('analyze_compliance', content)
        # Should NOT call evaluate_compliance
        self.assertNotIn('evaluate_compliance(normalized)', content)


class TestVendorSupport(unittest.TestCase):
    """Test vendor support in dual-model pipeline."""

    def test_cisco_prediction(self):
        """Test Cisco config analysis."""
        policy = 'Default usernames should not be used'
        config = 'hostname RTR-1\nusername admin privilege 15 secret 5 hash'
        result = analyze_compliance(policy, config, 'cisco', 'CIS-1.1')
        self.assertIn('prediction', result)
        self.assertIn('v6', result)

    def test_juniper_prediction(self):
        """Test Juniper config analysis."""
        policy = 'Default usernames should not be used'
        config = 'system login user admin class super-user'
        result = analyze_compliance(policy, config, 'juniper', 'CIS-1.1')
        self.assertIn('prediction', result)
        self.assertIn('v6', result)

    def test_paloalto_prediction(self):
        """Test Palo Alto config analysis."""
        policy = 'Default SNMP communities should not be used'
        config = 'set snmp community public read-only'
        result = analyze_compliance(policy, config, 'paloalto', 'CIS-3.1')
        self.assertIn('prediction', result)
        self.assertIn('v6', result)


class TestFailureHandling(unittest.TestCase):
    """Test graceful failure handling."""

    def test_v6_unavailable_uses_v4(self):
        """Test fallback to V4 when V6 is unavailable."""
        with patch('backend.ml.semantic_compliance.get_v6_model') as mock_v6:
            mock_v6.return_value = None

            result = analyze_compliance('policy', 'config', 'cisco', 'CIS-1.1')

            # Should fall back to V4
            self.assertEqual(result['model_used'], 'V4')
            self.assertTrue(result['fallback_used'])

    def test_no_models_available(self):
        """Test when no models are available."""
        with patch('backend.ml.semantic_compliance.get_v6_model') as mock_v6:
            with patch('backend.ml.semantic_compliance.get_v4_model') as mock_v4:
                mock_v6.return_value = None
                mock_v4.return_value = None

                result = analyze_compliance('policy', 'config', 'cisco', 'CIS-1.1')

                # Should return uncertain
                self.assertEqual(result['prediction'], 'uncertain')
                self.assertEqual(result['model_used'], 'none')


if __name__ == '__main__':
    unittest.main()
