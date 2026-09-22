# skillscan 手順書（Windows / uv / VS Code / Git）

`SKILL.md` と `install.sh` を**実行せずに**静的解析して、`allow / review / quarantine`
を判定するツールの使い方です。あなたのPC環境（uv・VS Code・Git 導入済み）を前提にしています。

---

## 0. 前提（すでに満たしているはず）

- Windows + PowerShell
- uv（Astral製）導入済み
- VS Code 導入済み
- Git 導入済み（`user.name` / `user.email` 設定済み）

確認：
```powershell
uv --version
git --version
```

---

## 1. プロジェクトを置く・開く

ダウンロードした `skillscan` フォルダを作業場所に置きます（例：`C:\dev\skillscan`）。

```powershell
cd C:\dev\skillscan
code .
```

VS Code のターミナル（`Ctrl + @`）以降ここで作業します。

---

## 2. 動作確認（同梱の検体で走らせる）

初回は uv が仮想環境を作り、プロジェクトをインストールします（数秒）。

```powershell
uv run skillscan tests\corpus --fail-on review
```

**期待される結果**：

- `benign\pdf-helper` … `✓ ALLOW`（score 0）
- `malicious\notes-sync` … `✗ QUARANTINE`（隠しコメントに注入）
- `malicious\quick-setup` … `✗ QUARANTINE`（`curl | sudo bash` する install.sh）

終了コードの確認（1 が返れば「危険を検知して落ちた」）：
```powershell
uv run skillscan tests\corpus --fail-on review; echo "exit=$LASTEXITCODE"
```

スモークテスト：
```powershell
uv run python tests\test_smoke.py
uv run python tests\test_frontmatter.py
# -> all ... tests passed
```

---

## 3. 実際のスキルをスキャンする

### 3-1. 単体のファイル / スキルフォルダ
```powershell
uv run skillscan "C:\path\to\SKILL.md"
uv run skillscan "C:\path\to\a-skill-folder"   # 同フォルダの install.sh も自動で対象
```

### 3-2. 自分の環境にあるスキルを一括点検
```powershell
uv run skillscan "$env:USERPROFILE\.claude\skills" --fail-on review
```

### 3-3. ネットから入手したスキルを「取り込む前に」検査する（重要）
**install.sh は絶対に実行しない**。クローン＝ただのファイル取得なので安全です。実行するのは skillscan だけ。

```powershell
# 例：オフェンシブ系スキル集を “陽性サンプル” として検査（実行はしない）
cd C:\dev
git clone https://github.com/SnailSploit/claude-red.git
uv run skillscan C:\dev\claude-red --fail-on review --format json > report.json
```

> ポイント：clone は取得だけ。`install.sh` や README の手順は走らせないこと。
> skillscan はファイルを読むだけで、危険な挙動は一切再現しません。

---

## 4. 出力の読み方

```
✗ QUARANTINE   score=71.6   [A:0.0 B:71.6 C:0.0]
                 ↑総合点        ↑A意図 B注入 C導入 の内訳
hard   : a forced-quarantine rule fired   ← 点数に関係なく強制隔離が発火

  pts  axis        region        finding / evidence
 ★11.2  injection   html_comment  exfil_action: send it to https://
  ↑★=強制隔離級  ↑検出軸      ↑どこに   ↑ルールID: 根拠(80字で切り詰め)
```

- **verdict**：`allow`（問題なし）/ `review`（人間が確認）/ `quarantine`（隔離＝取り込まない）
- **region**：`visible`（本文）より `html_comment`/`invisible`/`base64` などの**隠し領域**は倍率で加点
- **★**：`curl|bash` などの hard ルール、または隠し領域のインジェクション＝一発で quarantine
- **A軸（意図）は低weight**：正規のレッドチーム用スキルも攻撃用語を含むため、意図だけでは落とさない設計

機械可読が要るとき：
```powershell
uv run skillscan <対象> --format json
```

---

## 5. Git pre-commit フックに組み込む（未検証スキルの混入を防ぐ）

リポジトリで、`skills\` 配下に危険なスキルが commit されそうになったら止めます。
Git for Windows は付属の sh でフックを実行するので、以下の sh スクリプトで動きます。

`リポジトリ\.git\hooks\pre-commit`（拡張子なし）を作成：
```sh
#!/bin/sh
# ステージされた skills/ 配下を検査。quarantine があれば commit を止める。
if git diff --cached --name-only | grep -q '^skills/'; then
  echo "[skillscan] scanning skills/ ..."
  uv run skillscan skills --fail-on quarantine || {
    echo "[skillscan] 危険なスキルを検知したため commit を中止しました。"
    exit 1
  }
fi
exit 0
```

作成用ワンライナー（PowerShell、リポジトリ直下で実行）：
```powershell
@'
#!/bin/sh
if git diff --cached --name-only | grep -q "^skills/"; then
  echo "[skillscan] scanning skills/ ..."
  uv run skillscan skills --fail-on quarantine || { echo "[skillscan] 危険なスキルを検知したため commit を中止しました。"; exit 1; }
fi
exit 0
'@ | Set-Content -NoNewline -Encoding ascii .git\hooks\pre-commit
```

これで `git commit` 時に自動で走ります。手元で試すには：
```powershell
uv run skillscan skills --fail-on quarantine
```

---

## 6. CI（GitHub Actions）に組み込む

`.github\workflows\skillscan.yml`：
```yaml
name: skillscan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - name: Scan skills
        run: uv run skillscan skills --fail-on quarantine
```

PR に危険なスキルが含まれるとチェックが赤になり、マージをブロックできます。
（この「AIスキルの取り込みを CI で検証する」構成が、そのままポートフォリオ／職務経歴の実績になります。）

---

## 7. 検知ルールを足す（コードを触らず data だけ）

`src\skillscan\rules\` の JSON に 1 行足すだけで検知パターンを増やせます。

- `injection.json` … プロンプト注入・制御奪取の正規表現（B軸）
- `install.json` … install.sh の危険コマンド（C軸、`hard: true` は強制隔離）
- `intent.json` … 攻撃“意図”のカテゴリ語彙（A軸、低weight）

例：install.json に「`chmod 777` を検知」を追加
```json
{"id": "chmod_world", "weight": 3, "hard": false, "scope": "command", "regex": "(?i)chmod\\s+777"}
```
追加後、そのまま再実行すれば反映されます（ビルド不要）。

---

## 8. 精度を測る（評価ハーネス, v0.2〜）

ラベル付きコーパス（`tests\corpus\benign` / `malicious`）で検知率と誤検知を数値化します。
外部のスキル集を「良性と推定」して誤検知率の目安にもできます（clone のみ・スクリプトは実行しない）。

```powershell
uv run python -m skillscan.eval tests\corpus
uv run python -m skillscan.eval tests\corpus --external C:\dev\Anthropic-Cybersecurity-Skills\skills
```

レポートの `context` 列の意味：
- `directive` … モデルへの命令として書かれた地の文（満点で加点）
- `example:code_fence` / `example:quote` / `example:table` など … 例文として引用されたもの（×0.35に減点、無視はしない）
- `tag` … A軸（攻撃意図）。上限3点の“文脈情報”で、単独では review にならない

新しい検体を足したら `tests\corpus\malicious\<名前>\SKILL.md` に置いて再実行し、
`uv run python tests\test_smoke.py` と `uv run python tests\test_frontmatter.py` で回帰テストが通ることを確認します（pytest があれば `uv run --with pytest pytest -q tests` でも可）。

## 9. トラブルシュート

| 症状 | 対処 |
|------|------|
| `skillscan` が見つからない | プロジェクト直下（pyproject.toml のある場所）で `uv run skillscan ...` を実行しているか確認 |
| フックが動かない | ファイル名が `pre-commit`（拡張子なし）か、`skills/` にステージ差分があるか確認 |
| 日本語が文字化け | PowerShell を UTF-8 に：`chcp 65001`、または `--format json` を使う |
| `curl|bash` を含む正規のスキルまで落ちる | それは正しい挙動。取り込む前に人手レビュー対象にすべき信号です |

---

## 9. PDF/Wordファイルを検査する（docscan）

SKILL.md 用とは別に、PDF/Wordファイルの**間接的プロンプトインジェクション**（隠し文字・コメント・文書プロパティなどに埋め込まれた、AIへの指示文）だけを検査する `docscan` コマンドが同梱されています。マクロや埋め込みJavaScriptの検査は対象外です（それぞれ `oletools`、`pdfid` など専用ツールを使ってください）。

初回のみ、追加の依存関係（python-docx / pdfminer.six / pypdf）を入れます。

```powershell
uv sync --extra docscan
```

使い方:

```powershell
# 1ファイル
uv run docscan C:\path\to\report.pdf
uv run docscan C:\path\to\contract.docx

# フォルダごと（.pdf / .docx をまとめて）
uv run docscan C:\path\to\folder --fail-on review
```

動作確認（同梱の検体で走らせる）：

```powershell
uv run python tests\test_docscan.py
```

`benign\vendor-report.docx` が ALLOW、`malicious\hidden-run-injection.docx`（Wordの「隠し文字」書式に指示文を埋め込んだ検体）が QUARANTINE になれば正常です。

## 次の一手（v0.2 以降）

1. コードフェンスに攻撃文を隠す回避手口への耐性強化（命令形＋二人称の検出など）
2. Dual-LLM 隔離要約（スキルが“何を主張するか”をツールなし隔離モデルで要約）
3. 評価ハーネス（自作検体＋実在オフェンシブスキルで precision/recall を数値化）
