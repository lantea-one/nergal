namespace Nergal.Web;

/// <summary>A shared, keyboard-operable on/off form control. Unchecked switches omit their field, like native boolean inputs.</summary>
/// <param name="Name">Explicit form field name.</param>
/// <param name="Enabled">Current proposed form state; rendering never persists it.</param>
/// <param name="Label">Stable screen-reader label for the enabled feature; no text is drawn beside the switch.</param>
/// <param name="AccessibleLabel">Optional contextual name, for example a rule or account name.</param>
/// <param name="DescriptionId">Optional ID of associated guidance.</param>
/// <param name="FormId">Optional owning form when rendered outside the form element.</param>
/// <param name="Disabled">Whether interaction and submission are unavailable.</param>
public sealed record EnablementSwitchModel(string Name, bool Enabled, string Label,
    string? AccessibleLabel = null, string? DescriptionId = null, string? FormId = null, bool Disabled = false);
