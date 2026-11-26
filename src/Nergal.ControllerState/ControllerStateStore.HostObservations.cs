using System.Data.Common;
using System.Globalization;
using Nergal.Core.Controller;

namespace Nergal.ControllerState;

public sealed partial class ControllerStateStore
{
    /// <summary>Reads the latest retained authenticated status reply for a host, when available.</summary>
    public HostObservation? ReadHostObservation(Guid hostId) => Read((conn, tx) => ReadHostObservation(conn, tx, hostId));

    /// <summary>Records a newer authenticated observation from the controller's trusted dispatch path.</summary>
    /// <returns>Whether the observation was recorded. Older observations and missing registrations are ignored.</returns>
    /// <remarks>
    /// An authenticated settled reply can synchronize the registration's last-known revision within the same transaction.
    /// Supply the revision seen before dispatch to preserve an intervening registration update.
    /// An observation contains no desired policy, agent receipt, or authority to dispatch a change.
    /// </remarks>
    /// <exception cref="ArgumentException">The observation, UTC timestamp, or requested revision update is invalid.</exception>
    public bool RecordHostObservation(HostObservation observation, bool updateLastKnownRevision = false,
        ulong? expectedLastKnownRevision = null)
    {
        ArgumentNullException.ThrowIfNull(observation);
        if (observation.HostId == Guid.Empty || !Enum.IsDefined(observation.State) || observation.ObservedAtUtc.Offset != TimeSpan.Zero ||
            updateLastKnownRevision && (observation.ReportedRevision is null or 0 ||
                observation.State is not (HostObservationState.Matched or HostObservationState.Online)))
        {
            throw new ArgumentException("Invalid authenticated host observation.", nameof(observation));
        }

        return Write((conn, tx) =>
        {
            var id = observation.HostId.ToString("D");
            if (ScalarLong(conn, tx, "SELECT count(*) FROM hosts WHERE id=@id", ("@id", id)) == 0) { return false; }
            var previous = ReadHostObservation(conn, tx, observation.HostId);
            if (previous is not null && previous.ObservedAtUtc >= observation.ObservedAtUtc) { return false; }

            var revision = (object?)observation.ReportedRevision?.ToString(CultureInfo.InvariantCulture) ?? DBNull.Value;
            var time = observation.ObservedAtUtc.ToString("O", CultureInfo.InvariantCulture);
            var parameters = new (string, object)[] { ("@id", id), ("@state", (int)observation.State), ("@rev", revision), ("@time", time) };
            if (previous is null)
            {
                ExecuteNonQuery(conn, tx, """
                    INSERT INTO host_observations (host_id, state, reported_revision, observed_at_utc)
                    VALUES (@id, @state, @rev, @time)
                    """, parameters);
            }
            else
            {
                ExecuteNonQuery(conn, tx, """
                    UPDATE host_observations SET state=@state, reported_revision=@rev, observed_at_utc=@time WHERE host_id=@id
                    """, parameters);
            }

            if (updateLastKnownRevision)
            {
                var expected = (object?)expectedLastKnownRevision?.ToString(CultureInfo.InvariantCulture) ?? DBNull.Value;
                using var command = conn.CreateCommand();
                command.Transaction = tx;
                command.CommandText = """
                    UPDATE hosts SET last_known_revision=@rev
                    WHERE id=@id AND (@expected IS NULL OR last_known_revision=@expected)
                    """;
                AddParameter(command, "@rev", revision);
                AddParameter(command, "@id", id);
                AddParameter(command, "@expected", expected, System.Data.DbType.String);
                command.ExecuteNonQuery();
            }

            return true;
        });
    }

    private static HostObservation? ReadHostObservation(DbConnection conn, DbTransaction tx, Guid hostId)
    {
        using var command = conn.CreateCommand();
        command.Transaction = tx;
        command.CommandText = "SELECT state, reported_revision, observed_at_utc FROM host_observations WHERE host_id=@id";
        AddParameter(command, "@id", hostId.ToString("D"));
        using var reader = command.ExecuteReader();
        if (!reader.Read()) { return null; }

        var state = (HostObservationState)reader.GetInt32(0);
        var revisionText = reader.IsDBNull(1) ? null : reader.GetString(1);
        var revision = 0UL;
        if (!Enum.IsDefined(state) ||
            revisionText is not null && (!ulong.TryParse(revisionText, NumberStyles.None, CultureInfo.InvariantCulture, out revision) ||
                revisionText != revision.ToString(CultureInfo.InvariantCulture)) ||
            !DateTimeOffset.TryParseExact(reader.GetString(2), "O", CultureInfo.InvariantCulture, DateTimeStyles.None, out var observedAt) ||
            observedAt.Offset != TimeSpan.Zero)
        {
            throw new ControllerStateException("observation.corrupt");
        }

        return new HostObservation(hostId, state, revisionText is null ? null : revision, observedAt);
    }

    private const string HostObservationSchemaSql = """
        CREATE TABLE host_observations (
            host_id TEXT NOT NULL PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
            state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 5),
            reported_revision TEXT,
            observed_at_utc TEXT NOT NULL
        ) STRICT;
        """;
}
