import csv

def export_packets_to_csv(packets, filename):
    keys = ["no", "source", "destination", "protocol", "length", "time"]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(packets)