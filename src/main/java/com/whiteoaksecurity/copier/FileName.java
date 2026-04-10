package com.whiteoaksecurity.copier;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FileName {

    // 预编译正则：匹配 {内容}
    private static final Pattern PLACEHOLDER_PATTERN = Pattern.compile("\\{([^}]+)\\}");

    // 日期时间格式化器
    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("yyyyMMdd");
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HHmmss");

    /**
     * 构建文件名主方法
     * @param pattern 模板字符串，例如 "{s+100}_{date}.html"
     * @param sequence 当前序号 (s)
     * @return 最终文件名
     */
    public static String renderFileName(String pattern, int sequence) {

        if (pattern == null || pattern.trim().isEmpty()) {
            pattern = "{s}.html"; // 默认规则
        }

        Matcher matcher = PLACEHOLDER_PATTERN.matcher(pattern);
        StringBuffer sb = new StringBuffer();

        while (matcher.find()) {
            // 获取大括号内的表达式，例如 "s+100" 或 "date"
            String expression = matcher.group(1).trim();
            // 计算表达式的值
            String replacement = evaluateExpression(expression, sequence);
            // 替换
            matcher.appendReplacement(sb, replacement);
        }
        matcher.appendTail(sb);

        String fileName = sb.toString();

        // 1. 清洗非法字符 (保留原有逻辑)
        fileName = fileName.replaceAll("[\\\\/:*?\"<>|\\p{Cntrl}]", "_");
        fileName = fileName.trim();
        fileName = fileName.replaceAll("[.\\s]+$", "");

        // 2. 兜底逻辑
        if (fileName.isEmpty()) {
            fileName = String.valueOf(sequence);
        }

        // 3. 文件名校验与清洗
        fileName = sanitizeFileName(fileName);

        return fileName;
    }

    /**
     * 核心解析逻辑：处理 {} 中的内容
     * 支持：
     * - s (当前序号)
     * - s+100, s-10 (序号运算)
     * - date, time (时间)
     */
    private static String evaluateExpression(String expr, int sequence ) {
        // 1. 处理时间关键字
        if ("date".equalsIgnoreCase(expr)) {
            LocalDateTime now =  LocalDateTime.now();
            return now.format(DATE_FMT);
        }
        if ("time".equalsIgnoreCase(expr)) {
            LocalDateTime now =  LocalDateTime.now();
            return now.format(TIME_FMT);
        }

        // 2. 处理纯序号 s
        if ("s".equalsIgnoreCase(expr)) {
            return String.valueOf(sequence);
        }

        // 3. 处理算术表达式 (如 s+100, s-5)
        // 正则：匹配 s 后跟 + 或 - 号，再跟数字
        if (expr.matches("^s\\s*([+-])\\s*\\d+$")) {
            // 提取运算符
            char op = expr.contains("+") ? '+' : '-';
            // 提取数字部分 (去除 s 和运算符)
            int num = Integer.parseInt(expr.replaceAll("^s\\s*[+-]\\s*", ""));

            int result = sequence;
            if (op == '+') {
                result += num;
            } else {
                result -= num;
            }
            return String.valueOf(result);
        }

        // 4. 未知格式，原样返回（或者抛出异常，视需求而定）
        // 这里选择保留原样，防止破坏文件名结构
        return "{" + expr + "}";
    }


    /**
     * 文件名清洗工具
     */
    private static String sanitizeFileName(String fileName) {
        // 替换非法字符 (Windows/Linux 通用)
        fileName = fileName.replaceAll("[\\\\/:*?\"<>|\\p{Cntrl}]", "_");
        // 去除首尾空白
        fileName = fileName.trim();
        // 去除尾部点号 (防止生成 "file." 这种尴尬的文件名)
        fileName = fileName.replaceAll("[.\\s]+$", "");

        // 兜底：如果清洗后为空
        if (fileName.isEmpty()) {
            fileName = String.valueOf(java.util.UUID.randomUUID().hashCode());
        }

        return fileName;
    }
    // --- 测试入口 ---
    public static void main(String[] args) {
        int seq = 10;
        // 测试用例
        System.out.println(renderFileName("{s}.html", seq ));          // 输出: 10.html
        System.out.println(renderFileName("{s+100}.html", seq ));      // 输出: 110.html
        System.out.println(renderFileName("{s-5}.html", seq));        // 输出: 5.html
        System.out.println(renderFileName("log_{date}_{s}.txt", seq )); // 输出: log_20260410_10.txt
        System.out.println(renderFileName("backup_{s+1}_{time}.zip", seq)); // 输出: backup_11_153000.zip
    }
}