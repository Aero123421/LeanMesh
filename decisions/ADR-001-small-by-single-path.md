# ADR-001: 機能ではなく実装方式の数を減らす
Status: Accepted for spec v0.1 / hardware qualification pending

20hop、自動channel、機器移設という要求は削らない。一方、単一routing root、source-route、単一EDHOC profile、単一radio owner、単一Python serviceに固定する。普段のforwardはframe長に対してO(length)、近隣探索は固定16上限、全網topology計算はrootへ置く。設定や保守は同じ型付きobject engineを使う。

代償: root停止で新たな経路認可/承認が止まり、既存leaseが切れれば通信も停止する。源経路の長さでMTUが下がる。深い経路のbulk効率は低下する。これをHA/圧縮/分散合意を初期から足して隠さない。root冗長化・cache圧縮を足すのは実測不足を根拠に別ADRで決定する。

Revisit gate: 64node/20hop実RFの目標未達、rootRAM超過、許されない停止時間が製品要求になった場合。単に将来使うかもしれないという理由では拡張しない。
