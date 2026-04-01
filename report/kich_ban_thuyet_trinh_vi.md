# Kịch Bản Thuyết Trình Thực Nghiệm

## Mục tiêu

Tài liệu này là kịch bản nói tiếng Việt để thuyết trình dựa trực tiếp trên report của đề tài. Cách trình bày được thiết kế theo hướng an toàn, rõ ràng, và phù hợp khi chỉ cần mở report rồi giải thích cho giảng viên.

## Câu mở đầu

Kính thưa thầy, hôm nay em trình bày phần thực nghiệm của đề tài phát hiện hành vi ransomware bằng Wazuh.

Mục tiêu của phần thực nghiệm này không phải là chạy mã độc thật, mà là xây dựng một quy trình phát hiện có thể lặp lại, an toàn, và có số liệu để đánh giá. Vì lý do đó, em sử dụng nguồn telemetry công khai về Lockbit, sau đó chuẩn hóa dữ liệu, phân tích bằng pipeline Python, và mô phỏng luồng phát hiện bằng Wazuh chạy trên Docker.

## Phần 1: Giới thiệu bài toán

Ransomware là một trong những mối đe dọa nguy hiểm vì nó có thể mã hóa dữ liệu rất nhanh, gây gián đoạn hoạt động và ảnh hưởng trực tiếp đến tính sẵn sàng của hệ thống.

Trong thực tế, khó có thể dựa hoàn toàn vào chữ ký tĩnh, vì các họ ransomware thường thay đổi tên file, chuỗi, hoặc kỹ thuật thực thi. Vì vậy, hướng tiếp cận của em là phát hiện theo hành vi, tức là quan sát các dấu hiệu như thao tác với shadow copy, tạo ransom note, hoặc các artifact liên quan đến mã hóa.

## Phần 2: Kiến trúc thực nghiệm

Ở phần này, thầy có thể nhìn vào mục kiến trúc trong report.

Kiến trúc của em gồm 3 phần chính:

1. Nguồn dữ liệu công khai là bộ Lockbit Sysmon dataset từ Splunk attack_data.
2. Pipeline phân tích bằng Python để chuyển dữ liệu về một schema thống nhất, tính toán các chỉ số, và sinh biểu đồ cũng như bảng kết quả.
3. Wazuh manager chạy trên Docker để tái phát lại các sự kiện đã được chuẩn hóa và sinh cảnh báo theo rule tùy chỉnh.

Điểm quan trọng ở đây là em không chạy ransomware thật. Em dùng dữ liệu telemetry công khai và replay lại các sự kiện để chứng minh đường đi phát hiện. Cách làm này an toàn hơn, dễ lặp lại hơn, và phù hợp cho môi trường học thuật.

## Phần 3: Nguồn dữ liệu và cách xử lý

Về dữ liệu, em sử dụng public Lockbit Sysmon dataset. Từ bộ dữ liệu gốc này, em tách ra hai phần:

1. Một phần benign background, tức là các sự kiện nền không mang dấu hiệu nghi ngờ.
2. Một phần ransomware-labeled, tức là các sự kiện có liên quan đến hành vi đáng ngờ của Lockbit.

Sau đó, em chuẩn hóa các trường dữ liệu như:

- thời gian
- rule id
- rule level
- mô tả
- tiến trình hoặc file liên quan

Việc chuẩn hóa này giúp em có thể xử lý đồng nhất toàn bộ dữ liệu đầu vào, tính metric dễ hơn, và sinh report tự động.

## Phần 4: Ngưỡng phát hiện và phương pháp đánh giá

Trong thực nghiệm này, em chọn ngưỡng phát hiện là rule level lớn hơn hoặc bằng 10.

Từ đó, em tính các chỉ số chính gồm:

- True Positive
- False Positive
- False Negative
- Precision
- Recall
- F1-score
- False Positive Rate
- Time to Detect

Time to Detect được đo từ thời điểm bắt đầu mẫu tấn công trong metadata đến alert đầu tiên vượt ngưỡng phát hiện.

## Phần 5: Kết quả thực nghiệm

Đây là phần kết quả chính trong report.

Ở lần chạy hiện tại, hệ thống cho kết quả như sau:

- True Positives: 24
- False Positives: 0
- False Negatives: 0
- Precision: 100 phần trăm
- Recall: 100 phần trăm
- F1-score: 100 phần trăm
- False Positive Rate: 0 phần trăm
- Average Time to Detect: 0 giây

Nếu thầy hỏi vì sao kết quả lại rất sạch như vậy, thì em sẽ giải thích rõ:

Kết quả này phản ánh đúng workflow của mô hình demo, vì tập ransomware hiện tại được rút ra từ các sự kiện đáng ngờ của nguồn dữ liệu công khai. Do đó, nó phù hợp để chứng minh quy trình phát hiện, pipeline phân tích, và khả năng sinh cảnh báo, nhưng chưa nên diễn giải như một kết quả triển khai thực tế trong môi trường sản xuất.

Nói cách khác, điểm mạnh của phần này là tính lặp lại và tính minh bạch của quy trình; còn hạn chế là độ đa dạng dữ liệu benign và ransomware vẫn chưa lớn.

## Phần 6: Ý nghĩa của biểu đồ và bảng trong report

Khi trình bày biểu đồ, em có thể nói ngắn gọn như sau:

Biểu đồ thứ nhất thể hiện kết quả phát hiện tổng quát, cho thấy hệ thống nhận diện được toàn bộ các alert ransomware trong tập dữ liệu thực nghiệm mà không sinh false positive ở tập benign nền.

Biểu đồ thứ hai thể hiện các loại alert nổi bật nhất. Trong trường hợp này, nhóm hành vi liên quan đến shadow delete xuất hiện nhiều, đây là một dấu hiệu phù hợp với kỹ thuật cản trở khôi phục hệ thống thường thấy ở ransomware.

Bảng time to detect cho thấy cảnh báo đầu tiên xuất hiện gần như ngay lập tức sau thời điểm bắt đầu mẫu trong metadata. Với bộ dữ liệu hiện tại, giá trị này là 0 giây.

## Phần 7: Liên hệ với NIST CSF 2.0 và ISO 27001:2022

Một điểm em muốn nhấn mạnh là đề tài không chỉ dừng ở kỹ thuật phát hiện, mà còn được đặt trong bối cảnh quản trị và tiêu chuẩn an toàn thông tin.

Theo NIST CSF 2.0:

- Govern: em xác định rõ quy trình demo và trách nhiệm thao tác.
- Identify: em quản lý được nguồn dữ liệu công khai, tập dữ liệu dẫn xuất, replay artifact, và các kết quả sinh ra.
- Protect: em không sử dụng malware thật, mà dùng nguồn dữ liệu công khai và replay an toàn.
- Detect: đây là trọng tâm của đề tài, thông qua Wazuh rule, cảnh báo, và metric.
- Respond: em có bước phân tích cảnh báo và giải thích alert trong quá trình trình bày.
- Recover: em có thể tái tạo môi trường và sinh lại toàn bộ kết quả từ cùng một nguồn dữ liệu.

Theo ISO 27001:2022 Annex A:

- A.8.7 liên quan đến bảo vệ chống mã độc
- A.8.15 liên quan đến logging
- A.8.16 liên quan đến monitoring activities
- A.5.24 liên quan đến chuẩn bị và lập kế hoạch xử lý sự cố
- A.8.13 liên quan đến lưu giữ bằng chứng và kết quả phân tích

Phần mapping này cho thấy đề tài không chỉ mang tính kỹ thuật, mà còn có thể giải thích dưới góc nhìn kiểm soát và quản trị.

## Phần 8: Hạn chế của thực nghiệm

Để trình bày khách quan, em cần nêu rõ hạn chế:

1. Bộ dữ liệu hiện tại là dữ liệu công khai đã qua xử lý và gán nhãn, nên chưa phản ánh đầy đủ độ phức tạp của môi trường thực tế.
2. Chỉ số false positive rate hiện được tính trên tập benign nền được rút ra từ cùng nguồn dữ liệu, nên phạm vi đánh giá vẫn còn hẹp.
3. Mô hình hiện tại là behavior-based detection prototype, tức là nguyên mẫu phát hiện theo hành vi, chưa phải một hệ thống phòng thủ hoàn chỉnh trong môi trường doanh nghiệp.

## Phần 9: Hướng phát triển

Trong tương lai, đề tài có thể mở rộng theo các hướng sau:

1. Bổ sung thêm nhiều nguồn telemetry công khai khác để tăng độ đa dạng dữ liệu.
2. Tăng độ phong phú của tập benign để đánh giá false positive sát thực tế hơn.
3. Triển khai trong một lab cô lập mạnh hơn để kiểm chứng thêm các tình huống gần với môi trường thực.
4. Mở rộng bộ rule để bao phủ nhiều kỹ thuật ransomware hơn, thay vì tập trung chủ yếu vào Lockbit replay hiện tại.

## Câu kết

Tóm lại, phần thực nghiệm của em chứng minh được một quy trình phát hiện ransomware theo hành vi có thể triển khai an toàn, có thể lặp lại, và có khả năng sinh số liệu đánh giá rõ ràng.

Đóng góp chính của phần này là:

1. Sử dụng nguồn telemetry công khai có thể kiểm chứng.
2. Xây dựng pipeline phân tích tự động để sinh metric, biểu đồ, và report.
3. Kết nối phần kỹ thuật phát hiện với các khung chuẩn như NIST CSF 2.0 và ISO 27001:2022.

Em xin hết phần trình bày thực nghiệm.

## Phiên bản nói ngắn trong 2-3 phút

Nếu cần nói nhanh, có thể dùng đoạn sau:

Kính thưa thầy, ở phần thực nghiệm này em xây dựng một mô hình phát hiện ransomware theo hành vi bằng Wazuh. Thay vì chạy malware thật, em sử dụng bộ telemetry công khai về Lockbit từ Splunk để đảm bảo an toàn và khả năng lặp lại.

Từ dữ liệu gốc, em chuẩn hóa thành hai nhóm là benign background và ransomware-labeled, sau đó dùng pipeline Python để tính các chỉ số như precision, recall, F1-score, false positive rate và time to detect. Kết quả hiện tại cho thấy hệ thống phát hiện được 24 trên 24 alert ransomware, không có false positive trong tập benign nền, với precision và recall đều là 100 phần trăm.

Tuy nhiên, em cũng xác định rõ đây là một behavior-based detection prototype phục vụ mục tiêu chứng minh quy trình phát hiện và đánh giá, chứ chưa phải kết quả triển khai thực tế ở quy mô doanh nghiệp. Ngoài phần kỹ thuật, em còn đối chiếu kết quả với NIST CSF 2.0 và ISO 27001:2022 để cho thấy tính liên hệ với quản trị an toàn thông tin.

## Câu trả lời mẫu nếu thầy hỏi

### Nếu thầy hỏi: “Tại sao em không chạy mã độc thật?”

Em không chạy mã độc thật vì mục tiêu của bài là chứng minh quy trình phát hiện và đánh giá trong điều kiện an toàn, có thể lặp lại. Nếu chạy malware thật thì rủi ro cao hơn nhiều, khó kiểm soát hơn, và không cần thiết để chứng minh pipeline phân tích cũng như logic phát hiện.

### Nếu thầy hỏi: “Vậy kết quả 100 phần trăm có đáng tin không?”

Kết quả này đáng tin trong phạm vi mô hình demo hiện tại, vì nó phản ánh đúng tập dữ liệu đã được dẫn xuất từ nguồn telemetry công khai. Tuy nhiên, em không diễn giải nó như hiệu năng cuối cùng trong môi trường thực tế. Em coi đây là bằng chứng rằng workflow phân tích và phát hiện hoạt động đúng, còn để đánh giá thực chiến thì cần thêm dữ liệu đa dạng hơn.

### Nếu thầy hỏi: “Live replay chứng minh điều gì?”

Live replay chứng minh rằng các sự kiện đã được chuẩn hóa có thể đi qua Wazuh manager, khớp với custom rule, và sinh alert đúng như thiết kế. Nó chứng minh đường đi phát hiện hoạt động, nhưng không có nghĩa là em đang vận hành malware thật.

### Nếu thầy hỏi: “Đề tài này đóng góp gì?”

Đề tài đóng góp ở ba điểm: một là xây dựng quy trình phát hiện an toàn và lặp lại được; hai là tự động hóa phần đánh giá bằng metric và report; ba là liên hệ phần thực nghiệm kỹ thuật với khung chuẩn NIST CSF 2.0 và ISO 27001:2022.
