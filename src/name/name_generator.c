#include "name/name_generator.h"

#include "mongoose.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define MAX_GENERATED_NAMES 100000L

struct name_style {
  const char *const *family_names;
  size_t family_count;
  const char *const *given_heads;
  size_t head_count;
  const char *const *given_tails;
  size_t tail_count;
  bool family_first;
  bool concat_given;
};

static const char *const s_cn_family[] = {
    "Li", "Wang", "Zhang", "Liu", "Chen", "Yang", "Huang", "Zhao",
    "Wu", "Zhou", "Xu", "Sun", "Ma", "Zhu", "Hu", "Guo",
    "He", "Gao", "Lin", "Luo", "Zheng", "Liang", "Xie", "Song",
    "Tang", "Deng", "Han", "Feng", "Cao", "Peng", "Zeng", "Xiao",
    "Tian", "Dong", "Yuan", "Pan", "Yu", "Jiang", "Cai", "Ye",
    "Cheng", "Wei", "Su", "Lu", "Ding", "Ren", "Shen", "Yao",
    "Fan", "Liao", "Zou", "Xiong", "Jin", "Tan", "Qin", "Bai",
    "Hou", "Duan", "Shi", "Long", "Wan", "Qian", "Yin", "Chang",
    "Kong", "Qiu", "Mo", "Rao", "Gong", "Kang", "Mao", "Shao",
    "Meng", "Qiao", "Ruan", "Ni", "Mei", "Yan", "An", "Qi",
    "Pei", "Hao", "Mu", "Cui", "Dai", "Fang", "Fu", "Gu",
    "Hong", "Ji", "Lian", "Lei", "Miao", "Ning", "Qu", "Shan"};

static const char *const s_cn_given_head[] = {
    "An", "Bai", "Bo", "Chen", "Cheng", "Chun", "Da", "Dong",
    "Fang", "Fei", "Feng", "Guang", "Hai", "Han", "Hao", "Hong",
    "Hua", "Hui", "Jia", "Jian", "Jing", "Jun", "Kai", "Ke",
    "Kun", "Lei", "Liang", "Lin", "Ling", "Ming", "Nan", "Ning",
    "Peng", "Qiang", "Qing", "Ran", "Rui", "Shan", "Tao", "Tian",
    "Wei", "Wen", "Xiang", "Xiao", "Xin", "Yan", "Yang", "Yi",
    "Yong", "Yu", "Yuan", "Yue", "Zhe", "Zhen", "Zhi", "Zhong",
    "Zi", "Yun", "Si", "Xuan", "Mu", "Nuo", "Qian", "Yao"};

static const char *const s_cn_given_tail[] = {
    "an", "bo", "chen", "cheng", "da", "dong", "en", "fang",
    "fei", "feng", "guang", "hai", "han", "hao", "heng", "hong",
    "hua", "hui", "jia", "jian", "jie", "jing", "jun", "kai",
    "kun", "lan", "lei", "li", "liang", "lin", "ling", "long",
    "ming", "nan", "ning", "peng", "qiang", "qing", "ran", "rui",
    "shan", "tao", "tian", "wei", "wen", "xiang", "xiao", "xin",
    "yang", "yi", "yue", "yun", "zhe", "zhen", "zhi", "xuan",
    "yao", "nuo", "qian", "siyu", "yifan", "haoran", "yuchen", "ruoxi"};

static const char *const s_west_family[] = {
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
    "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez",
    "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore",
    "Jackson", "Martin", "Lee", "Perez", "Thompson", "White",
    "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
    "Walker", "Young", "Allen", "King", "Wright", "Scott",
    "Torres", "Nguyen", "Hill", "Flores", "Green", "Adams",
    "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner",
    "Diaz", "Parker", "Cruz", "Edwards", "Collins", "Reyes",
    "Stewart", "Morris", "Morales", "Murphy", "Cook", "Rogers",
    "Gutierrez", "Ortiz", "Morgan", "Cooper", "Peterson", "Bailey",
    "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox",
    "Ward", "Richardson", "Watson", "Brooks", "Chavez", "Wood",
    "James", "Bennett", "Gray", "Mendoza", "Ruiz", "Hughes",
    "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers"};

static const char *const s_west_first[] = {
    "James", "Avery", "Jordan", "Morgan", "Taylor", "Riley",
    "Casey", "Cameron", "Quinn", "Alex", "Jamie", "Parker",
    "Rowan", "Reese", "Emerson", "Finley", "Harper", "Logan",
    "Sawyer", "Blake", "Elliot", "Hayden", "Skyler", "Drew",
    "Robin", "Kai", "Noah", "Liam", "Mason", "Ethan",
    "Lucas", "Henry", "Jacob", "Daniel", "Matthew", "Samuel",
    "Owen", "Caleb", "Nathan", "Isaac", "Miles", "Leo",
    "Ryan", "Adrian", "Nolan", "Julian", "Aaron", "Connor",
    "Maya", "Emma", "Olivia", "Sophia", "Isabella", "Mia",
    "Amelia", "Charlotte", "Evelyn", "Abigail", "Emily", "Ella",
    "Grace", "Chloe", "Lily", "Nora", "Zoe", "Hazel",
    "Violet", "Aurora", "Naomi", "Lucy", "Claire", "Alice",
    "Sadie", "Ivy", "Ruby", "Eva", "Elena", "Cora"};

static const char *const s_west_middle[] = {
    "James", "Lee", "Ray", "Quinn", "Morgan", "Avery", "Blair", "Sage",
    "Reed", "Lane", "Grey", "Drew", "Skye", "Jude", "Kai", "Noel",
    "Dean", "Cole", "Finn", "Miles", "Grant", "Evan", "Owen", "Paul",
    "Wade", "Rhys", "Tate", "Nico", "Jules", "Robin", "Shawn", "Ellis",
    "Rose", "Mae", "June", "Hope", "Grace", "Belle", "Wren", "Iris",
    "Claire", "Eve", "Pearl", "Faye", "Ruth", "Joy", "Lynn", "Paige",
    "Brooke", "Faith", "Dawn", "Rae", "Leigh", "Jade", "Noor", "Bryn",
    "Arden", "Rowan", "Sloan", "Remy", "Winter", "River", "Lake", "Vale"};

static const char *const s_jp_family[] = {
    "Sato", "Suzuki", "Takahashi", "Tanaka", "Watanabe", "Ito",
    "Yamamoto", "Nakamura", "Kobayashi", "Kato", "Yoshida", "Yamada",
    "Sasaki", "Yamaguchi", "Matsumoto", "Inoue", "Kimura", "Hayashi",
    "Shimizu", "Yamazaki", "Mori", "Abe", "Ikeda", "Hashimoto",
    "Ishikawa", "Nakajima", "Maeda", "Fujita", "Ogawa", "Goto",
    "Okada", "Hasegawa", "Murakami", "Kondo", "Ishii", "Saito",
    "Sakamoto", "Endo", "Aoki", "Fujii", "Nishimura", "Fukuda",
    "Ota", "Miura", "Fujiwara", "Okamoto", "Matsuda", "Nakagawa"};

static const char *const s_jp_given_head[] = {
    "Haru", "Yuu", "Sora", "Kou", "Ren", "Riku", "Nao", "Aki",
    "Kazu", "Taka", "Masa", "Ryo", "Dai", "Yoshi", "Kei", "Shin",
    "Hiro", "Tomo", "Kaito", "Hayato", "Yui", "Hina", "Saku", "Mei",
    "Aoi", "Rin", "Mio", "Hana", "Aka", "Riko", "Koha", "Yuna",
    "Nana", "Miyu", "Mina", "Emi", "Rena", "Mika", "Kana", "Sayo"};

static const char *const s_jp_given_tail[] = {
    "to", "ki", "ya", "ma", "ta", "hei", "suke", "rou",
    "ichi", "ji", "sei", "go", "nosuke", "hiko", "haru", "nori",
    "ka", "ko", "mi", "na", "ri", "ho", "ne", "yo",
    "e", "sa", "ha", "no", "zu", "kae", "mari", "yuki",
    "saki", "nami", "rina", "mana", "shiori", "asuka", "mika", "erika"};

static const char *const s_global_family[] = {
    "Ivanov", "Petrov", "Smirnov", "Kuznetsov", "Popov", "Volkov",
    "Sokolov", "Mikhailov", "Fedorov", "Orlov", "Garcia", "Rodriguez",
    "Fernandez", "Sanchez", "Gomez", "Moreno", "Alvarez", "Romero",
    "Martin", "Bernard", "Dubois", "Robert", "Petit", "Durand",
    "Leroy", "Moreau", "Laurent", "Lefebvre", "Mueller", "Schmidt",
    "Schneider", "Fischer", "Weber", "Meyer", "Wagner", "Becker",
    "Hoffmann", "Schulz", "Kim", "Park", "Choi", "Jung",
    "Kang", "Yoon", "Jang", "Lim", "Khan", "Ahmed",
    "Ali", "Hassan", "Singh", "Sharma", "Kumar", "Patel",
    "Nair", "Rao", "Silva", "Santos", "Costa", "Oliveira",
    "Pereira", "Rossi", "Bianchi", "Ricci"};

static const char *const s_global_first[] = {
    "Alexander", "Dmitry", "Mikhail", "Ivan", "Sergey", "Andrei",
    "Nikolai", "Alexey", "Pavel", "Kirill", "Maria", "Anna",
    "Elena", "Natalia", "Olga", "Irina", "Daria", "Polina",
    "Antonio", "Jose", "Manuel", "Francisco", "Javier", "Daniel",
    "Carlos", "Miguel", "Lucia", "Sofia", "Elena", "Paula",
    "Claudia", "Valeria", "Jean", "Pierre", "Michel", "Nicolas",
    "Julien", "Lucas", "Antoine", "Hugo", "Marie", "Camille",
    "Sophie", "Julie", "Lea", "Chloe", "Maximilian", "Leon",
    "Lukas", "Felix", "Jonas", "Noah", "Elias", "Finn",
    "Hannah", "Clara", "Emilia", "Minjun", "Seojun", "Doyun",
    "Jiho", "Hyunwoo", "Seoyeon", "Minseo", "Jiwoo", "Yuna",
    "Aarav", "Vivaan", "Aditya", "Arjun", "Rohan", "Anaya",
    "Diya", "Isha", "Fatima", "Omar", "Yusuf", "Zara"};

static const char *const s_global_middle[] = {
    "Noor", "Rafi", "Samir", "Kamal", "Nadia", "Leila", "Amir", "Mina",
    "Dev", "Raj", "Anil", "Kiran", "Nikhil", "Priya", "Meera", "Asha",
    "Luis", "Mateo", "Diego", "Rafael", "Elisa", "Marta", "Rosa", "Nina",
    "Luca", "Marco", "Paolo", "Enzo", "Giulia", "Bianca", "Chiara", "Lina",
    "Jae", "Min", "Soo", "Hyun", "Seo", "Won", "Jin", "Ara"};

static const struct name_style s_styles[] = {
    {s_cn_family, ARRAY_COUNT(s_cn_family), s_cn_given_head,
     ARRAY_COUNT(s_cn_given_head), s_cn_given_tail,
     ARRAY_COUNT(s_cn_given_tail), true, true},
    {s_west_family, ARRAY_COUNT(s_west_family), s_west_first,
     ARRAY_COUNT(s_west_first), s_west_middle,
     ARRAY_COUNT(s_west_middle), false, false},
    {s_jp_family, ARRAY_COUNT(s_jp_family), s_jp_given_head,
     ARRAY_COUNT(s_jp_given_head), s_jp_given_tail,
     ARRAY_COUNT(s_jp_given_tail), true, true},
    {s_global_family, ARRAY_COUNT(s_global_family), s_global_first,
     ARRAY_COUNT(s_global_first), s_global_middle,
     ARRAY_COUNT(s_global_middle), false, false},
};

static uint64_t random_u64(void) {
  uint64_t value = 0;
  if (!mg_random(&value, sizeof(value))) {
    value = ((uint64_t) rand() << 32) ^ (uint64_t) rand();
  }
  return value;
}

static uint64_t random_bounded(uint64_t count) {
  return count == 0 ? 0 : random_u64() % count;
}

static uint64_t gcd_u64(uint64_t a, uint64_t b) {
  while (b != 0) {
    uint64_t t = a % b;
    a = b;
    b = t;
  }
  return a;
}

static uint64_t pick_unique_step(uint64_t capacity) {
  uint64_t step;
  if (capacity <= 1) return 1;
  do {
    step = random_bounded(capacity - 1) + 1;
  } while (gcd_u64(step, capacity) != 1);
  return step;
}

static uint64_t hash_name(const char *name) {
  uint64_t hash = 1469598103934665603ULL;
  while (*name) {
    hash ^= (unsigned char) *name++;
    hash *= 1099511628211ULL;
  }
  return hash;
}

static size_t seen_table_size(long count) {
  size_t size = 16;
  size_t target = (size_t) count * 2U;
  while (size < target) size <<= 1U;
  return size;
}

static bool remember_name(char **seen, size_t seen_size, const char *name) {
  size_t mask = seen_size - 1U;
  size_t pos = (size_t) hash_name(name) & mask;

  for (size_t i = 0; i < seen_size; i++) {
    char *entry = seen[pos];
    if (entry == NULL) {
      seen[pos] = strdup(name);
      return seen[pos] != NULL;
    }
    if (strcmp(entry, name) == 0) return false;
    pos = (pos + 1U) & mask;
  }
  return false;
}

static void free_seen_names(char **seen, size_t seen_size) {
  if (seen == NULL) return;
  for (size_t i = 0; i < seen_size; i++) free(seen[i]);
  free(seen);
}

static uint64_t style_capacity(const struct name_style *style) {
  return (uint64_t) style->family_count * (uint64_t) style->head_count *
         (uint64_t) style->tail_count;
}

static uint64_t total_capacity(void) {
  uint64_t total = 0;
  for (size_t i = 0; i < ARRAY_COUNT(s_styles); i++) {
    total += style_capacity(&s_styles[i]);
  }
  return total;
}

static const struct name_style *style_for_index(uint64_t *index) {
  for (size_t i = 0; i < ARRAY_COUNT(s_styles); i++) {
    uint64_t capacity = style_capacity(&s_styles[i]);
    if (*index < capacity) return &s_styles[i];
    *index -= capacity;
  }
  return &s_styles[ARRAY_COUNT(s_styles) - 1];
}

static void build_name_from_index(uint64_t index, char *full_name,
                                  size_t full_len, char *given,
                                  size_t given_len, char *family,
                                  size_t family_len) {
  const struct name_style *style = style_for_index(&index);
  size_t tail_index = (size_t) (index % style->tail_count);
  size_t head_index;
  size_t family_index;
  const char *head;
  const char *tail;

  index /= style->tail_count;
  head_index = (size_t) (index % style->head_count);
  index /= style->head_count;
  family_index = (size_t) (index % style->family_count);

  head = style->given_heads[head_index];
  tail = style->given_tails[tail_index];
  mg_snprintf(family, family_len, "%s", style->family_names[family_index]);
  if (tail[0] == '\0') {
    mg_snprintf(given, given_len, "%s", head);
  } else if (style->concat_given) {
    mg_snprintf(given, given_len, "%s%s", head, tail);
  } else {
    mg_snprintf(given, given_len, "%s %s", head, tail);
  }

  if (style->family_first) {
    mg_snprintf(full_name, full_len, "%s %s", family, given);
  } else {
    mg_snprintf(full_name, full_len, "%s %s", given, family);
  }
}

int name_generator_generate(struct generated_name *name) {
  uint64_t capacity = total_capacity();
  uint64_t index;

  if (name == NULL || capacity == 0) return -1;
  index = random_bounded(capacity);
  build_name_from_index(index, name->full_name, sizeof(name->full_name),
                        name->given_name, sizeof(name->given_name),
                        name->family_name, sizeof(name->family_name));
  return 0;
}

char *name_generator_json(long count) {
  struct mg_iobuf io = {0, 0, 0, 1024};
  struct mg_iobuf items = {0, 0, 0, 1024};
  uint64_t capacity = total_capacity();
  uint64_t start = random_bounded(capacity);
  uint64_t step = pick_unique_step(capacity);
  uint64_t attempts = 0;
  long emitted = 0;
  size_t seen_size;
  char **seen;

  if (count <= 0) count = 20;
  if (count > MAX_GENERATED_NAMES) count = MAX_GENERATED_NAMES;
  if ((uint64_t) count > capacity) count = (long) capacity;

  seen_size = seen_table_size(count);
  seen = (char **) calloc(seen_size, sizeof(*seen));

  while (emitted < count && attempts < capacity) {
    uint64_t index = (start + attempts * step) % capacity;
    char full_name[192];
    char given[128];
    char family[96];

    build_name_from_index(index, full_name, sizeof(full_name),
                          given, sizeof(given), family, sizeof(family));
    attempts++;
    if (seen != NULL && !remember_name(seen, seen_size, full_name)) continue;

    if (emitted > 0) mg_xprintf(mg_pfn_iobuf, &items, ",");
    mg_xprintf(mg_pfn_iobuf, &items,
               "{%m:%m,%m:%m,%m:%m}",
               MG_ESC("full_name"), MG_ESC(full_name),
               MG_ESC("given_name"), MG_ESC(given),
               MG_ESC("family_name"), MG_ESC(family));
    emitted++;
  }

  mg_xprintf(mg_pfn_iobuf, &io, "{%m:%ld,%m:%llu,%m:[",
             MG_ESC("count"), emitted,
             MG_ESC("capacity"), (unsigned long long) capacity,
             MG_ESC("items"));
  mg_iobuf_add(&io, io.len, items.buf, items.len);
  mg_xprintf(mg_pfn_iobuf, &io, "]}");
  mg_iobuf_add(&io, io.len, "", 1);
  mg_iobuf_free(&items);
  free_seen_names(seen, seen_size);
  return (char *) io.buf;
}
