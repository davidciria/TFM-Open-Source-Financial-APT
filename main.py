from mitreattack.stix20 import MitreAttackData
import matplotlib.pyplot as plt

def attack_tecniques_chart(attack_patt_groups, id_name, top=None):
    # Your dictionary with attack names and percentages
    attack_dict = {}
    for apg in attack_patt_groups:
        num_attacks = len(attack_patt_groups[apg])
        if num_attacks > 2:
            attack_dict[id_name[apg]] = num_attacks

    # Sort the dictionary by values in descending order
    sorted_attacks = sorted(attack_dict.items(), key=lambda x: x[1], reverse=True)

    if top:
        sorted_attacks = sorted_attacks[0:top]

    # Extract sorted attack names and percentages
    attack_names, percentages = zip(*sorted_attacks)

    # Create a bar chart
    plt.bar(attack_names, percentages, color='skyblue')

    # Set labels and title
    plt.xlabel('Techniques Names')
    plt.ylabel('Number of Groups')
    plt.title('Techniques Used by Groups')

    # Rotate x-axis labels for better readability
    plt.xticks(rotation=45, ha='right')

    # Adjust layout to prevent x-axis label cutoff
    plt.tight_layout()

    plt.savefig("attack_tecniques_chart.png")

    # Show the plot
    # plt.show()

    return attack_names, percentages

def get_financial_groups(mitre_attack_data):
    key_words = ['banks', 'financial inst', 'bank']

    groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
    financial_groups = []
    for index, group in enumerate(groups):
        description = group.get('description', '')
        
        for kw in key_words:
            if kw in description.lower():
                financial_groups.append(group)
                break
    
    print(f"Financial groups: {len(financial_groups)}")

    return financial_groups

def attack_patterns_descriptions(attack_names, name_id, id_patt):
    with open("attack_tecniques_descriptions.txt", "w") as f:
        for an in attack_names:
            attack_pat_id = name_id[an]
            attack_pat_obj = id_patt[attack_pat_id]

            description = attack_pat_obj['description']

            f.write(f"------- {an} -------\n")
            f.write(f"{description}")
            f.write("\n\n")



def process_attack_patterns(financial_groups, mitre_attack_data):
    attack_patt_groups = {}
    id_name = {}
    id_patt = {}

    for fg in financial_groups:
        techniques = mitre_attack_data.get_techniques_used_by_group(fg['id'])
        parent_techniques = []
        for t in techniques:
            obj = t['object']
            id = obj['id']
            id_name[id] = obj['name']
            id_patt[id] = obj

            if obj['x_mitre_is_subtechnique']:
                parents = mitre_attack_data.get_parent_technique_of_subtechnique(id)
                if len(parents) == 1:
                    parent_technique = parents[0]
                    parent_obj = parent_technique['object']
                    parent_id = parent_obj['id']
                    # First time this parent technique has been seen for this group.
                    if parent_id not in parent_techniques:
                        parent_techniques.append(parent_id)

                        # If is subtechnique, get parent technique.
                        id = parent_obj['id']
                        id_name[id] = parent_obj['name']
                        id_patt[id] = obj
                    else:
                    # The parent technique has been considered before for this group.
                        continue
                else:
                    print("Error getting parent technique")
                    raise Exception("Error getting parent technique")
            
            if id in attack_patt_groups:
                attack_patt_groups[id].append(fg['name'])
            else:
                attack_patt_groups[id] = [fg['name']]

    attack_names, percentages = attack_tecniques_chart(attack_patt_groups, id_name, top=10)
    name_id = {value: key for key, value in id_name.items()}
    attack_patterns_descriptions(attack_names, name_id, id_patt)


def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    financial_groups = get_financial_groups(mitre_attack_data)

    process_attack_patterns(financial_groups, mitre_attack_data)


if __name__ == "__main__":
    main()