"""Test suite tự động cho Bài tập 2: Decoder, Preprocessor & Flow Tracker.
Bao gồm đầy đủ 14 test cases bắt buộc từ T01 đến T14 theo đặc tả trong đề bài.
"""

import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from models.event import IDSEvent
# from models.flow import FlowRecord
from decoder import Decoder
# from preprocessor import Preprocessor
# from flow_tracker import FlowTracker


class TestIDSModules(unittest.TestCase):

    def setUp(self):
        self.decoder = Decoder()
        # self.preprocessor = Preprocessor()
        # self.flow_tracker = FlowTracker()

    def test_T01_http_url_decode(self):
        """T01: HTTP URL decode: URI chứa percent-encoding -> decoded URI đúng; raw URI còn nguyên."""
        raw_uri = "/search?q=%27%20OR%201%3D1"
        event = IDSEvent(
            packet_id=1,
            timestamp=100.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            transport_proto="TCP",
            app_proto="HTTP",
            app_data={"uri": raw_uri}
        )
        self.decoder.decode(event)
        self.assertEqual(event.app_data.get("uri"), raw_uri, "Raw URI phải được giữ nguyên")
        self.assertEqual(event.app_data.get("uri_decoded"), "/search?q=' OR 1=1", "Decoded URI phải chính xác")

    def test_T02_html_entity_decode(self):
        """T02: HTML entity: &lt;...&gt; trong text HTTP -> decoded text đúng, không crash."""
        raw_body = "Message: &lt;script&gt;alert('test')&lt;/script&gt; &amp; &quot;hello&quot;"
        event = IDSEvent(
            packet_id=2,
            timestamp=101.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            transport_proto="TCP",
            app_proto="HTTP",
            app_data={"body": raw_body}
        )
        self.decoder.decode(event)
        expected = "Message: <script>alert('test')</script> & \"hello\""
        self.assertEqual(event.app_data.get("body_decoded"), expected)

    def test_T03_smtp_base64_qp_decode(self):
        """T03: SMTP Base64/QP: MIME body có encoding phù hợp -> decoded body đúng + decode_status."""
        # 1. Base64
        event_b64 = IDSEvent(
            packet_id=3,
            timestamp=102.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            transport_proto="TCP",
            app_proto="SMTP",
            app_data={"raw_body": "SGVsbG8gSVAgVHJhY2tlciE=", "mime_encoding": "base64"}
        )
        self.decoder.decode(event_b64)
        self.assertEqual(event_b64.app_data.get("decoded_body"), "Hello IP Tracker!")
        self.assertEqual(event_b64.app_data.get("decode_status"), "success")

        # 2. Quoted-Printable
        event_qp = IDSEvent(
            packet_id=4,
            timestamp=103.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            transport_proto="TCP",
            app_proto="SMTP",
            app_data={"raw_body": "Hello=20World=3D=21", "mime_encoding": "quoted-printable"}
        )
        self.decoder.decode(event_qp)
        self.assertEqual(event_qp.app_data.get("decoded_body"), "Hello World=!")
        self.assertEqual(event_qp.app_data.get("decode_status"), "success")

    def test_T04_invalid_bytes_safe_decode(self):
        """T04: Invalid bytes: Payload không phải UTF-8 hợp lệ -> đánh dấu lỗi/partial; chương trình tiếp tục."""
        event = IDSEvent(
            packet_id=5,
            timestamp=104.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            transport_proto="TCP",
            raw_payload=b"\x80\xff\xfe\x00\xaa"
        )
        # Không được văng exception
        self.decoder.decode(event)
        self.assertEqual(event.decode_status, "partial")
        self.assertIn("Invalid UTF-8", event.decode_error)

    # def test_T05_normalization(self):
    #     """T05: Normalization: header/protocol/domain khác kiểu chữ/format -> representation sau preprocess nhất quán."""
    #     event = IDSEvent(
    #         packet_id=6,
    #         timestamp=105.1234567,
    #         src_ip=" 10.0.0.1 ",
    #         dst_ip=" 10.0.0.2 ",
    #         network_proto="ipv4",
    #         transport_proto="tcp",
    #         app_proto="http",
    #         app_data={
    #             "headers": {"Host": "WWW.EXAMPLE.COM.", "USER-AGENT": "curl/7.68.0"},
    #             "uri": "///api//v1//user"
    #         }
    #     )
    #     self.preprocessor.process(event)
    #     self.assertEqual(event.network_proto, "IPv4")
    #     self.assertEqual(event.transport_proto, "TCP")
    #     self.assertEqual(event.app_proto, "HTTP")
    #     self.assertEqual(event.src_ip, "10.0.0.1")
    #     self.assertEqual(event.dst_ip, "10.0.0.2")
    #     self.assertEqual(event.app_data["uri"], "/api/v1/user")
    #     self.assertIn("host", event.app_data["headers"])
    #     self.assertIn("user-agent", event.app_data["headers"])

    # def test_T06_missing_field_handling(self):
    #     """T06: Missing field: event thiếu field không bắt buộc -> xử lý null/[] nhất quán, không exception."""
    #     event = IDSEvent(
    #         packet_id=7,
    #         timestamp=106.0,
    #         src_ip="10.0.0.1",
    #         dst_ip="10.0.0.2",
    #         transport_proto="TCP",
    #         app_proto="HTTP"
    #         # Thiếu hoàn toàn app_data
    #     )
    #     self.preprocessor.process(event)
    #     self.assertIsInstance(event.app_data, dict)
    #     self.assertEqual(event.app_data.get("headers"), {})
    #     self.assertIsNone(event.app_data.get("body"))

    # def test_T07_tcp_handshake_state(self):
    #     """T07: TCP handshake: SYN -> SYN/ACK -> ACK -> 1 flow; trạng thái ESTABLISHED."""
    #     tracker = FlowTracker()
    #     p1 = IDSEvent(packet_id=8, timestamp=200.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=10001, dst_port=80,
    #                   transport_proto="TCP", transport_flags="SYN", packet_len=60)
    #     p2 = IDSEvent(packet_id=9, timestamp=200.01, src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=10001,
    #                   transport_proto="TCP", transport_flags="SYN ACK", packet_len=60)
    #     p3 = IDSEvent(packet_id=10, timestamp=200.02, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=10001, dst_port=80,
    #                   transport_proto="TCP", transport_flags="ACK", packet_len=54)

    #     tracker.process_event(p1)
    #     tracker.process_event(p2)
    #     flow = tracker.process_event(p3)

    #     self.assertEqual(flow.state, "ESTABLISHED")
    #     self.assertEqual(flow.packet_count, 3)

    # def test_T08_bidirectional_flow(self):
    #     """T08: Bidirectional flow: packet A->B và B->A cùng 5-tuple đảo chiều -> cùng flow_id, đúng direction."""
    #     tracker = FlowTracker()
    #     fwd_pkt = IDSEvent(packet_id=11, timestamp=201.0, src_ip="192.168.1.10", dst_ip="93.184.216.34", src_port=44332, dst_port=80,
    #                        transport_proto="TCP", transport_flags="SYN", packet_len=60)
    #     bwd_pkt = IDSEvent(packet_id=12, timestamp=201.02, src_ip="93.184.216.34", dst_ip="192.168.1.10", src_port=80, dst_port=44332,
    #                        transport_proto="TCP", transport_flags="SYN ACK", packet_len=60)

    #     tracker.process_event(fwd_pkt)
    #     tracker.process_event(bwd_pkt)

    #     self.assertEqual(fwd_pkt.flow_id, bwd_pkt.flow_id)
    #     self.assertEqual(fwd_pkt.flow_direction, "forward")
    #     self.assertEqual(bwd_pkt.flow_direction, "backward")

    # def test_T09_tcp_close_state(self):
    #     """T09: TCP close: FIN/ACK hoặc RST -> flow chuyển CLOSED/RESET phù hợp."""
    #     tracker = FlowTracker()
    #     # Established flow
    #     p_est = IDSEvent(packet_id=13, timestamp=202.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=5000, dst_port=80,
    #                      transport_proto="TCP", transport_flags="ACK", packet_len=54)
    #     flow = tracker.process_event(p_est)
    #     flow.state = "ESTABLISHED"

    #     # FIN packet
    #     p_fin = IDSEvent(packet_id=14, timestamp=202.1, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=5000, dst_port=80,
    #                      transport_proto="TCP", transport_flags="FIN ACK", packet_len=54)
    #     tracker.process_event(p_fin)
    #     self.assertEqual(flow.state, "CLOSING")

    #     # Response FIN/ACK
    #     p_fin_ack = IDSEvent(packet_id=15, timestamp=202.15, src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=5000,
    #                          transport_proto="TCP", transport_flags="FIN ACK", packet_len=54)
    #     tracker.process_event(p_fin_ack)
    #     self.assertEqual(flow.state, "CLOSED/RESET")

    # def test_T10_udp_flow_tracking(self):
    #     """T10: UDP query/response: DNS UDP hai chiều -> 1 UDP flow, packet/byte count đúng."""
    #     tracker = FlowTracker()
    #     q = IDSEvent(packet_id=16, timestamp=300.0, src_ip="192.168.1.100", dst_ip="8.8.8.8", src_port=53535, dst_port=53,
    #                  transport_proto="UDP", app_proto="DNS", packet_len=75)
    #     r = IDSEvent(packet_id=17, timestamp=300.05, src_ip="8.8.8.8", dst_ip="192.168.1.100", src_port=53, dst_port=53535,
    #                  transport_proto="UDP", app_proto="DNS", packet_len=140)

    #     tracker.process_event(q)
    #     flow = tracker.process_event(r)

    #     self.assertEqual(q.flow_id, r.flow_id)
    #     self.assertEqual(flow.packet_count, 2)
    #     self.assertEqual(flow.byte_count, 215)
    #     self.assertEqual(flow.fwd_packet_count, 1)
    #     self.assertEqual(flow.bwd_packet_count, 1)

    # def test_T11_concurrent_flows(self):
    #     """T11: Concurrent flows: >= 2 flow có endpoint/port khác nhau -> không gộp nhầm flow."""
    #     tracker = FlowTracker()
    #     flow1_pkt = IDSEvent(packet_id=18, timestamp=400.0, src_ip="10.0.0.1", dst_ip="1.1.1.1", src_port=1001, dst_port=80,
    #                          transport_proto="TCP", packet_len=60)
    #     flow2_pkt = IDSEvent(packet_id=19, timestamp=400.0, src_ip="10.0.0.1", dst_ip="2.2.2.2", src_port=1002, dst_port=80,
    #                          transport_proto="TCP", packet_len=60)

    #     tracker.process_event(flow1_pkt)
    #     tracker.process_event(flow2_pkt)

    #     self.assertNotEqual(flow1_pkt.flow_id, flow2_pkt.flow_id)
    #     self.assertEqual(tracker.state_table.count(), 2)

    # def test_T12_idle_timeout(self):
    #     """T12: Idle timeout: flow không có packet mới quá timeout -> flow hết hạn và bị loại khỏi active table."""
    #     tracker = FlowTracker(tcp_idle_timeout=5.0, udp_idle_timeout=2.0)
    #     pkt = IDSEvent(packet_id=20, timestamp=100.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=80,
    #                    transport_proto="TCP", packet_len=60)
    #     tracker.process_event(pkt)
    #     self.assertEqual(tracker.state_table.count(), 1)

    #     # Quét timeout tại thời điểm 106.0s (> 5.0s timeout)
    #     expired = tracker.flush_expired(106.0)
    #     self.assertEqual(len(expired), 1)
    #     self.assertFalse(expired[0].is_active)
    #     self.assertEqual(tracker.state_table.count(), 0)

    # def test_T13_statistics(self):
    #     """T13: Statistics: nhiều packet hai chiều -> packet/byte/flag counters và duration đúng."""
    #     tracker = FlowTracker()
    #     p1 = IDSEvent(packet_id=21, timestamp=500.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=8000, dst_port=80,
    #                   transport_proto="TCP", transport_flags="SYN", packet_len=100)
    #     p2 = IDSEvent(packet_id=22, timestamp=502.5, src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=8000,
    #                   transport_proto="TCP", transport_flags="SYN ACK", packet_len=200)

    #     tracker.process_event(p1)
    #     flow = tracker.process_event(p2)

    #     self.assertEqual(flow.packet_count, 2)
    #     self.assertEqual(flow.byte_count, 300)
    #     self.assertEqual(flow.fwd_byte_count, 100)
    #     self.assertEqual(flow.bwd_byte_count, 200)
    #     self.assertEqual(flow.syn_count, 2)
    #     self.assertEqual(flow.ack_count, 1)
    #     self.assertAlmostEqual(flow.duration, 2.5, places=3)

    # def test_T14_malformed_event(self):
    #     """T14: Malformed event: event invalid/unsupported -> không crash; status/reason phù hợp."""
    #     bad_event = IDSEvent(
    #         packet_id=23,
    #         timestamp=-1.0,
    #         src_ip="invalid_ip_format",
    #         dst_ip="10.0.0.2",
    #         src_port=999999,  # Port vượt ngoài dải 0-65535
    #         dst_port=80,
    #         transport_proto="TCP"
    #     )
    #     self.preprocessor.process(bad_event)
    #     self.assertEqual(bad_event.preprocess_status, "invalid")
    #     self.assertEqual(bad_event.processing_action, "alert")
    #     self.assertIsNotNone(bad_event.preprocess_reason)


if __name__ == "__main__":
    unittest.main()