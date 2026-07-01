#ifndef APP_OUTLOOK_POOL_H
#define APP_OUTLOOK_POOL_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>

// try_fetch_code 的特殊返回值: 该邮箱的母邮箱不在 outlook 池中(不归 outlook007 接码管)
#define OUTLOOK_POOL_NOT_MINE (-2)

// ---- 前端 / HTTP 管理 ----
// 邮箱池列表 JSON: {items:[{id,email,code_api_url,alias_count,in_use,...}], workspace_id, join_mode}
char *outlook_pool_list_json(sqlite3 *db);
// 批量导入 "母邮箱----接码URL"(换行分隔), 返回 {ok,total_count,saved_count,invalid_count,duplicate_count,errors}
char *outlook_pool_import_json(sqlite3 *db, const char *text);
// 按 id 删除
int outlook_pool_delete_ids(sqlite3 *db, const long *ids, size_t count);
// 保存全局配置(加入的目标 workspace id / 加入方式)
int outlook_pool_save_config(sqlite3 *db, const char *workspace_id,
                             const char *join_mode);

// ---- 注册流程: 单线程占用锁 ----
// 原子取一个可用母邮箱并加锁; 返回 0 成功(填 email/code_api_url/out_id), -1 无可用
int outlook_pool_claim(sqlite3 *db, char *email, size_t email_len,
                       char *code_api_url, size_t code_api_url_len,
                       long *out_id, char *error, size_t error_len);
// 释放占用; success=true 时 alias_count+1
int outlook_pool_release(sqlite3 *db, long id, bool success);

// ---- 注册流程: 接码 ----
// 若 alias_email 的母邮箱在池中, 用其 code_api_url 拉取最新邮件并提取 6 位验证码
// 返回 1=命中, 0=未到, -1=错误, OUTLOOK_POOL_NOT_MINE=母邮箱不在池中
int outlook_pool_try_fetch_code(sqlite3 *db, const char *alias_email,
                                long min_received_at, char *code,
                                size_t code_len, char *error, size_t error_len);

// ---- workspace 加入子流程 ----
// 读取全局配置的目标 workspace id(调用方 free); 未配置返回空串
char *outlook_pool_workspace_id(sqlite3 *db);

// 别名邮箱 -> 母邮箱(去掉 local 的 +子标签); 无 + 时原样返回
void outlook_pool_alias_to_mother(const char *alias, char *out, size_t out_len);

#endif
